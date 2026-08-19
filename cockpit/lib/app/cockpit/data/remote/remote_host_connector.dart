import 'dart:async';
import 'dart:io';

import 'package:cockpit/app/cockpit/data/remote/dartssh_host_connection.dart';
import 'package:cockpit/app/cockpit/data/remote/ssh_channel_duplex.dart';
import 'package:cockpit/app/cockpit/data/remote/ssh_tunnel.dart';
import 'package:cockpit/app/cockpit/domain/entities/remote_host.dart';
import 'package:cockpit/app/core/utils/platform_kind.dart';
import 'package:cockpit_core/cockpit_core.dart';
import 'package:cockpit_remote/cockpit_remote.dart';

/// Estado observável da conexão com um host (badge/telas da UI, plano 58).
enum RemoteHostPhase {
  idle,
  openingTunnel,
  installingServer,
  connecting,
  connected,
  reconnecting,
  failed,
}

/// Falha tipada da abertura (a frase nasce na UI via context.t; `detail` é
/// texto cru de terceiros: stderr do ssh, mensagem de socket).
enum RemoteHostErrorKind {
  sshUnreachable,
  serverInstallFailed,
  versionMismatch,
  protocol,
}

class RemoteHostException implements Exception {
  const RemoteHostException(this.kind, [this.detail]);
  final RemoteHostErrorKind kind;
  final String? detail;

  @override
  String toString() => 'RemoteHostException(${kind.name}: $detail)';
}

/// Conecta a um [RemoteHost] via túnel SSH e entrega o [TerminalService]
/// remoto daquele host (plano 58, Wave 2).
///
/// Fluxo de abertura (as fases alimentam o loading progressivo da UI):
/// 1. túnel SSH pro socket do cockpit-server remoto;
/// 2. conexão + handshake; se o servidor não existe lá, **bootstrap pelo
///    próprio SSH** (Install server): sobe binário + dylib do bundle local e
///    inicia o servidor remoto;
/// 3. serviço pronto. Queda do túnel → [phase] = reconnecting e retry com
///    backoff; sessões sobrevivem no servidor remoto (semântica tmux).
class RemoteHostConnector {
  RemoteHostConnector(
    this.host, {
    required this.localServerBinaryResolver,
    this.passwordResolver,
  });

  final RemoteHost host;

  /// Resolve o binário local do cockpit-server (o mesmo do sidecar) usado
  /// como fonte do bootstrap. Mac→Mac de mesma arquitetura; a validação de
  /// arch remota é o `--version` pós-instalação falhar alto.
  final String? Function() localServerBinaryResolver;

  /// Resolve a senha SSH do host (auth por senha), lida do Keychain sob
  /// demanda. `null` = auth por chave (default). Plano 60, Wave C.
  final Future<String?> Function()? passwordResolver;

  SshTunnel? _tunnel;
  DartSshHostConnection? _dartConn;

  /// Status de turno (spinner/chime) vindo do host pelo protocolo (Wave G).
  /// Reassina a cada (re)conexão; broadcast pra o controller repassar à VM.
  final _turnStatus = StreamController<RemoteTurnStatus>.broadcast();
  StreamSubscription<RemoteTurnStatus>? _turnSub;
  Stream<RemoteTurnStatus> get turnStatus => _turnStatus.stream;

  void _bindTurnStatus() {
    _turnSub?.cancel();
    _turnSub = _service?.turnStatus.listen(_turnStatus.add);
  }

  /// Senha resolvida na abertura atual (auth por senha); só em memória.
  String? _password;
  RemoteConnection? _connection;
  RemoteTerminalService? _service;
  Future<RemoteTerminalService>? _inflight;

  final StreamController<RemoteHostPhase> _phases =
      StreamController.broadcast();
  RemoteHostPhase phase = RemoteHostPhase.idle;

  Stream<RemoteHostPhase> get phases => _phases.stream;

  void _setPhase(RemoteHostPhase value) {
    phase = value;
    _phases.add(value);
  }

  /// Serviço de terminais do host, abrindo (ou reabrindo) a conexão se
  /// preciso. Lança [RemoteHostException] tipada em falha de abertura.
  Future<RemoteTerminalService> ensure() {
    final connection = _connection;
    if (connection != null && connection.isOpen) {
      return Future.value(_service!);
    }
    return _inflight ??= _open()
        .then((service) {
          // TODA reabertura bem-sucedida anuncia o serviço novo — não só a que
          // vem do retry/botão. Os gateways de terminal dependem deste evento
          // pra trocar o serviço e re-anexar; quando ele só saía pelo caminho
          // do retry, uma reconexão disparada por qualquer outra ação deixava as
          // abas presas ao serviço morto (teclado mudo).
          _retryStep = 0;
          if (!_disposed) _reconnected.add(service);
          return service;
        })
        .catchError((Object e) {
          // Falha de ABERTURA (host offline, SSH recusado, server ausente)
          // também entra no ciclo de retry. Sem isto, só a queda de um túnel já
          // estabelecido reagendava — e o caso mais comum, tentar abrir um host
          // que está fora do ar, ficava parado em `failed` para sempre.
          _scheduleRetry();
          throw e;
        })
        .whenComplete(() => _inflight = null);
  }

  /// Serviço de arquivos do host (mesma conexão dos terminais). Conecta se
  /// preciso; usado pelo picker de pasta remota.
  Future<RemoteFileService> fileService() async {
    await ensure();
    return RemoteFileService(_connection!);
  }

  /// Serviço git do host (mesma conexão). Conecta se preciso.
  Future<RemoteGitService> gitService() async {
    await ensure();
    return RemoteGitService(_connection!);
  }

  /// Serviço de DB do host (mesma conexão). Conecta se preciso.
  Future<RemoteDbService> dbService() async {
    await ensure();
    return RemoteDbService(_connection!);
  }

  Future<RemoteTerminalService> _open() async {
    _setPhase(
      phase == RemoteHostPhase.connected
          ? RemoteHostPhase.reconnecting
          : RemoteHostPhase.openingTunnel,
    );
    // Senha (auth por senha) lida do Keychain uma vez por abertura; null =
    // auth por chave. Guardada só em memória, pro bootstrap reusar.
    _password = await passwordResolver?.call();
    // Mobile (plano 59): transporte dartssh2 (Dart puro), sem binário `ssh` nem
    // bootstrap (decisão D — não instala server). Desktop segue no system-ssh.
    if (isMobilePlatform) return _openMobile();
    final SshTunnel tunnel;
    try {
      tunnel = await SshTunnel.open(
        target: host.sshTarget,
        port: host.port,
        password: _password,
      );
    } on SshTunnelException catch (e) {
      _setPhase(RemoteHostPhase.failed);
      throw RemoteHostException(RemoteHostErrorKind.sshUnreachable, e.detail);
    }
    _tunnel = tunnel;
    unawaited(tunnel.closed.then((_) => _onTunnelClosed()));

    _setPhase(RemoteHostPhase.connecting);
    var connection = await _tryProtocol(tunnel);
    if (connection == null) {
      // Servidor ausente/parado no host: bootstrap pelo próprio SSH.
      _setPhase(RemoteHostPhase.installingServer);
      await _installAndStartServer();
      connection = await _tryProtocol(tunnel, attempts: 20);
      if (connection == null) {
        _setPhase(RemoteHostPhase.failed);
        throw const RemoteHostException(
          RemoteHostErrorKind.serverInstallFailed,
        );
      }
    }
    _connection = connection;
    _service = RemoteTerminalService(connection);
    _bindTurnStatus();
    _setPhase(RemoteHostPhase.connected);
    return _service!;
  }

  /// Abertura no mobile: conecta via dartssh2, resolve `$HOME` do host e
  /// encaminha pro socket UNIX remoto. Sem bootstrap — se o server não está lá,
  /// falha com erro claro (o mobile não instala server, decisão D).
  Future<RemoteTerminalService> _openMobile() async {
    // sshTarget é `user@host` (sem porta); a porta vive em host.port.
    if (host.user.isEmpty || host.host.isEmpty) {
      _setPhase(RemoteHostPhase.failed);
      throw const RemoteHostException(
        RemoteHostErrorKind.sshUnreachable,
        'ssh_target_no_user',
      );
    }
    final endpoint = SshEndpoint(host.user, host.host, host.port);
    final conn = DartSshHostConnection(endpoint, password: _password);
    try {
      await conn.connect();
    } on DartSshException catch (e) {
      _setPhase(RemoteHostPhase.failed);
      throw RemoteHostException(
        RemoteHostErrorKind.sshUnreachable,
        e.detail ?? e.code,
      );
    }
    _dartConn = conn;
    unawaited(conn.done.then((_) => _onTunnelClosed()));

    _setPhase(RemoteHostPhase.connecting);
    try {
      final home = await conn.run(r'printf %s "$HOME"');
      final remoteSocket = '$home/.cockpit/cockpit-server.sock';
      final channel = await conn.forwardUnix(remoteSocket);
      final connection = await RemoteConnection.connectOn(
        SshChannelDuplex(channel),
        clientName: 'cockpit-ipad',
      );
      _connection = connection;
      _service = RemoteTerminalService(connection);
      _bindTurnStatus();
      _setPhase(RemoteHostPhase.connected);
      return _service!;
    } on TerminalException catch (e) {
      _setPhase(RemoteHostPhase.failed);
      if (e.detail == 'version_mismatch') {
        throw const RemoteHostException(RemoteHostErrorKind.versionMismatch);
      }
      // Server ausente no host: mobile não instala (decisão D).
      throw RemoteHostException(
        RemoteHostErrorKind.serverInstallFailed,
        e.detail,
      );
    } catch (e) {
      _setPhase(RemoteHostPhase.failed);
      throw RemoteHostException(RemoteHostErrorKind.protocol, '$e');
    }
  }

  Future<RemoteConnection?> _tryProtocol(
    SshTunnel tunnel, {
    int attempts = 1,
  }) async {
    for (var i = 0; i < attempts; i++) {
      if (i > 0) {
        await Future<void>.delayed(Duration(milliseconds: 100 + i * 50));
      }
      try {
        final localPort = tunnel.localPort;
        return await RemoteConnection.connectOn(
          localPort != null
              ? await SocketRemoteDuplex.connectTcp('127.0.0.1', localPort)
              : await SocketRemoteDuplex.connectUnix(tunnel.localSocketPath!),
          clientName: 'cockpit-gui-ssh',
        );
      } on TerminalException catch (e) {
        // Handshake respondeu com erro = servidor existe mas incompatível.
        if (e.detail == 'version_mismatch') {
          _setPhase(RemoteHostPhase.failed);
          throw RemoteHostException(RemoteHostErrorKind.versionMismatch);
        }
        // protocol/transport → servidor provavelmente ausente; tenta de novo.
      } catch (_) {
        // socket remoto sem listener; segue pro retry/bootstrap.
      }
    }
    return null;
  }

  /// "Install server": sobe binário + dylib pelo canal SSH (stdin → arquivo,
  /// sem depender de scp/rsync no host) e inicia o servidor remoto no socket
  /// padrão.
  ///
  /// `--exit-on-idle 120` + `--idle-keeps-sessions`: o servidor encerra sozinho
  /// ~2min depois que ninguém mais o usa (sem órfão no host), MAS nunca enquanto
  /// houver sessão viva. Sem a segunda flag, dois minutos de desconexão matavam
  /// o que estivesse rodando lá — um agente aberto, um build, um vim — que é o
  /// oposto da promessa de retomar de onde parou. Persistência 24/7 gerida por
  /// launchd/systemd fica pra Wave 3.
  ///
  /// Servidor antigo no host ignora a flag desconhecida (o parser dele busca
  /// por índice), então a instalação segue funcionando; só não ganha o
  /// comportamento novo até ser reinstalado.
  static const _remoteIdleSeconds = 120;
  Future<void> _installAndStartServer() async {
    final binary = localServerBinaryResolver();
    if (binary == null) {
      throw const RemoteHostException(
        RemoteHostErrorKind.serverInstallFailed,
        'local cockpit-server binary not found',
      );
    }
    // Bundle: <root>/bin/cockpit-server + <root>/lib/*.dylib (anaki + pty). O
    // exe resolve as dylibs em @executable_path/../lib, então preservamos o
    // layout no host (~/.cockpit/server/{bin,lib}).
    final bundleRoot = File(binary).parent.parent.path;
    final libDir = Directory('$bundleRoot/lib');

    Future<void> push(String local, String remote) async {
      final bytes = await File(local).readAsBytes();
      final (code, stderrText) = await SshTunnel.run(
        host.sshTarget,
        'mkdir -p ~/.cockpit/server/bin ~/.cockpit/server/lib && '
        'cat > $remote && chmod +x $remote',
        stdinBytes: bytes,
        port: host.port,
        password: _password,
      );
      if (code != 0) {
        throw RemoteHostException(
          RemoteHostErrorKind.serverInstallFailed,
          stderrText,
        );
      }
    }

    await push(binary, '~/.cockpit/server/bin/cockpit-server');
    if (libDir.existsSync()) {
      for (final f in libDir.listSync().whereType<File>()) {
        if (!f.path.endsWith('.dylib') && !f.path.endsWith('.so')) continue;
        await push(f.path, '~/.cockpit/server/lib/${f.uri.pathSegments.last}');
      }
    }
    // CLI `cockpit` ao lado do server (plano 60, Wave G): o server a acha via
    // _besideServer e instala o hook do agente no ~/.claude do host. Só se
    // estiver no bundle local (build_server.sh a embarca).
    final cliLocal = File('$bundleRoot/bin/cockpit');
    if (cliLocal.existsSync()) {
      await push(cliLocal.path, '~/.cockpit/server/bin/cockpit');
    }

    final (code, stderrText) = await SshTunnel.run(
      host.sshTarget,
      // nohup + redirects: o servidor sobrevive ao fim desta sessão ssh. O pty
      // vem do ../lib do bundle; o anaki resolve por rpath.
      'COCKPIT_PTY_DYLIB=\$HOME/.cockpit/server/lib/libcockpit_pty.dylib '
      'nohup \$HOME/.cockpit/server/bin/cockpit-server '
      '--socket \$HOME/.cockpit/cockpit-server.sock '
      '--exit-on-idle $_remoteIdleSeconds '
      '--idle-keeps-sessions '
      '>/dev/null 2>&1 & echo started',
      port: host.port,
      password: _password,
    );
    if (code != 0) {
      throw RemoteHostException(
        RemoteHostErrorKind.serverInstallFailed,
        stderrText,
      );
    }
  }

  // --- Reconexão automática -------------------------------------------------
  //
  // Backoff crescente que NUNCA desiste (decisão do usuário): 1s, 2s, 4s, 8s,
  // 15s e daí 30s fixo. O teto no intervalo (e não no número de tentativas) é
  // o que mantém "insiste pra sempre" sem martelar a rede — num iPad, um socket
  // a cada 30s é desprezível perto de tentar a cada segundo.
  static const List<Duration> _backoff = <Duration>[
    Duration(seconds: 1),
    Duration(seconds: 2),
    Duration(seconds: 4),
    Duration(seconds: 8),
    Duration(seconds: 15),
    Duration(seconds: 30),
  ];

  Timer? _retryTimer;
  int _retryStep = 0;
  bool _disposed = false;

  /// Emite quando a conexão é REFEITA — os gateways de terminal usam pra
  /// re-anexar suas sessões (o serviço é outro objeto após reabrir).
  final _reconnected = StreamController<RemoteTerminalService>.broadcast();
  Stream<RemoteTerminalService> get reconnected => _reconnected.stream;

  void _onTunnelClosed() {
    if (_disposed || _aborting) return;
    if (phase == RemoteHostPhase.connected) {
      _setPhase(RemoteHostPhase.reconnecting);
    }
    _scheduleRetry();
  }

  void _scheduleRetry() {
    if (_disposed || _retryTimer != null) return;
    final delay = _backoff[_retryStep.clamp(0, _backoff.length - 1)];
    if (_retryStep < _backoff.length - 1) _retryStep++;
    _retryTimer = Timer(delay, () {
      _retryTimer = null;
      _attemptReconnect();
    });
  }

  Future<void> _attemptReconnect() async {
    if (_disposed) return;
    final connection = _connection;
    if (connection != null && connection.isOpen) return;
    try {
      // `ensure()` dedup pelo `_inflight`, então tentativa concorrente com uma
      // ação do usuário não abre dois túneis. Quem anuncia o serviço novo (e
      // zera o backoff) é o próprio `ensure`, para valer em qualquer caminho.
      await ensure();
    } on Object {
      // Falhou de novo: reagenda. A fase já foi pra failed dentro de _open().
      if (!_disposed) {
        _setPhase(RemoteHostPhase.reconnecting);
        _scheduleRetry();
      }
    }
  }

  /// Reconecta AGORA (botão da UI): descarta o backoff acumulado, **aborta a
  /// tentativa em curso** e abre uma nova. Sem efeito se a conexão está viva.
  ///
  /// O abort é o que faz o botão ter efeito de verdade. Sem ele, `ensure()`
  /// devolvia o `_inflight` — e com o host fora do ar há quase sempre uma
  /// abertura em voo (o retry automático dispara a cada 1-30s e cada tentativa
  /// leva até 15s pra estourar), então o clique só pegava carona numa tentativa
  /// já pendurada: da UI, parecia que o botão não fazia nada.
  Future<void> reconnectNow() async {
    if (_disposed) return;
    _retryTimer?.cancel();
    _retryTimer = null;
    _retryStep = 0;
    // Feedback imediato: o abort abaixo pode levar um instante (fechar socket,
    // esperar a tentativa pendurada morrer) e o clique não pode parecer inerte.
    _setPhase(RemoteHostPhase.openingTunnel);
    await _abortCurrentAttempt();
    if (_disposed) return;
    await _attemptReconnect();
  }

  /// Derruba conexão/transporte/tentativa atuais para que a próxima abertura
  /// comece do zero. Fechar o transporte faz a tentativa pendurada estourar na
  /// hora, em vez de esperar o timeout.
  Future<void> _abortCurrentAttempt() async {
    final inflight = _inflight;
    final connection = _connection;
    final tunnel = _tunnel;
    final dartConn = _dartConn;
    _connection = null;
    _service = null;
    _tunnel = null;
    _dartConn = null;
    // O fechamento é NOSSO, deliberado: o `closed`/`done` do transporte vai
    // disparar [_onTunnelClosed], que agendaria um retry concorrente com o que
    // este método está prestes a fazer.
    _aborting = true;
    try {
      await connection?.close();
    } on Object {
      // já morto.
    }
    try {
      await tunnel?.close();
    } on Object {
      // já morto.
    }
    try {
      await dartConn?.close();
    } on Object {
      // já morto.
    }
    if (inflight != null) {
      try {
        await inflight;
      } on Object {
        // a tentativa abortada falha — é o esperado.
      }
    }
    _aborting = false;
  }

  /// Fechamento provocado por nós ([_abortCurrentAttempt]) não deve agendar
  /// retry: quem abortou já vai reabrir.
  bool _aborting = false;

  Future<void> dispose() async {
    _disposed = true;
    _retryTimer?.cancel();
    _retryTimer = null;
    await _reconnected.close();
    await _turnSub?.cancel();
    await _turnStatus.close();
    await _connection?.close();
    await _tunnel?.close();
    await _dartConn?.close();
    _connection = null;
    _service = null;
    await _phases.close();
  }
}
