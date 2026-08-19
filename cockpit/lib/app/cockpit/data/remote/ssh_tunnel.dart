import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// Túnel SSH para o socket do `cockpit-server` de um host remoto (plano 58,
/// Wave 2, decisão G): usa o binário `ssh` DO SISTEMA — nada de biblioteca
/// SSH nem crypto nossa. `~/.ssh/config`, chaves, agent e ProxyJump valem de
/// graça; se `ssh <target>` funciona no terminal do usuário, funciona aqui.
///
/// O forward é de socket UDS→UDS: o servidor remoto escuta só em localhost
/// (nunca expõe porta de rede) e este túnel materializa aquele socket num
/// path local. Pro cliente, o resultado é indistinguível do loopback.
class SshTunnel {
  SshTunnel._(this._process, this.localSocketPath, this.target);

  final Process _process;

  /// Socket local que espelha o socket remoto do cockpit-server.
  final String localSocketPath;
  final String target;

  final Completer<void> _closed = Completer();

  /// Completa quando o túnel cair (queda de rede, ssh morto). Quem observa
  /// decide reconectar (banner "reconnecting" na UI, decisão de UX da W2).
  Future<void> get closed => _closed.future;

  bool get isOpen => !_closed.isCompleted;

  /// Sobe o túnel e espera o socket local ficar conectável.
  ///
  /// Auth por CHAVE (default, [password] null): `BatchMode=yes` — falha alto se
  /// o ssh precisar de senha (a UI mostra o erro tipado). Auth por SENHA
  /// ([password] setado, plano 60 Wave C): injeta a senha via `SSH_ASKPASS`
  /// (helper efêmero 0600) e aceita host key nova (`accept-new`); nada de senha
  /// em argv nem em variável de ambiente.
  static Future<SshTunnel> open({
    required String target,
    int port = 22,
    String? password,
    String remoteSocketPath = r'$HOME/.cockpit/cockpit-server.sock',
    Duration timeout = const Duration(seconds: 15),
  }) async {
    // No Windows, `Directory.systemTemp.path` começa com letra de drive + ':'
    // (ex: `C:\Users\...\Temp`), que colide com o separador `local:remoto` do
    // `-L` (streamlocal) — o ssh lê o ':' do drive como separador e recusa
    // com "Bad local forwarding specification". Path local ABSOLUTO segue
    // guardado em [localPath] (é o que o resto do código usa pra conectar de
    // verdade); só o argumento passado ao `-L` usa o nome relativo + `cwd` no
    // tempdir, sem ':' nenhum.
    final tempDir = Directory.systemTemp.path;
    final localFileName =
        'cockpit-ssh-${DateTime.now().microsecondsSinceEpoch}.sock';
    final localPath = '$tempDir${Platform.pathSeparator}$localFileName';

    final askpass = await _Askpass.create(password);
    final authOpts = _authOpts(port: port, usingPassword: password != null);

    try {
      // O forward streamlocal do OpenSSH NÃO resolve path relativo nem expande
      // `~`/`$HOME` — precisa de path absoluto. Resolvemos a home remota com um
      // exec rápido antes de abrir o túnel.
      var resolvedRemote = remoteSocketPath;
      if (remoteSocketPath.contains(r'$HOME')) {
        // `ConnectTimeout` limita o connect TCP, mas não um handshake/auth que
        // trava depois de conectado — daí o teto explícito também aqui. Este
        // exec roda ANTES do laço com deadline de [open]; sem teto, ele é o
        // ponto onde a abertura fica pendurada indefinidamente.
        final result =
            await Process.run('ssh', [
              ...authOpts,
              target,
              r'printf %s "$HOME"',
            ], environment: askpass?.env).timeout(
              timeout,
              onTimeout: () =>
                  throw SshTunnelException('timeout resolving remote home'),
            );
        if (result.exitCode != 0) {
          throw SshTunnelException((result.stderr as String).trim());
        }
        resolvedRemote = remoteSocketPath.replaceFirst(
          r'$HOME',
          (result.stdout as String).trim(),
        );
      }

      final process = await Process.start('ssh', [
        '-N', // só forward, sem shell
        ...authOpts,
        '-o', 'ExitOnForwardFailure=yes',
        '-o', 'ServerAliveInterval=10',
        '-o', 'ServerAliveCountMax=3',
        '-o', 'StreamLocalBindUnlink=yes',
        '-L',
        Platform.isWindows
            ? '$localFileName:$resolvedRemote'
            : '$localPath:$resolvedRemote',
        target,
      ], environment: askpass?.env, workingDirectory: tempDir);

      final stderrBuffer = StringBuffer();
      process.stderr.transform(utf8.decoder).listen(stderrBuffer.write);
      unawaited(process.stdout.drain<void>());

      final tunnel = SshTunnel._(process, localPath, target);
      unawaited(
        process.exitCode.then((_) {
          if (!tunnel._closed.isCompleted) tunnel._closed.complete();
        }),
      );

      // Pronto = socket local existe E o ssh não morreu. Não dá pra "testar"
      // conectando aqui: o forward UDS só valida o lado remoto na 1ª conexão
      // de verdade, então erros de destino aparecem na conexão do protocolo.
      final deadline = DateTime.now().add(timeout);
      while (!File(localPath).existsSync()) {
        if (tunnel._closed.isCompleted) {
          throw SshTunnelException(stderrBuffer.toString().trim());
        }
        if (DateTime.now().isAfter(deadline)) {
          process.kill();
          throw SshTunnelException(
            'timeout waiting for tunnel; ${stderrBuffer.toString().trim()}',
          );
        }
        await Future<void>.delayed(const Duration(milliseconds: 50));
      }
      return tunnel;
    } finally {
      // Auth já ocorreu (o socket apareceu, ou falhou/estourou) — o helper de
      // senha não é mais necessário. Removê-lo evita deixar a senha no disco.
      await askpass?.dispose();
    }
  }

  /// Teto do connect TCP de QUALQUER invocação do ssh daqui.
  ///
  /// Sem isto, um host desligado cujo pacote é DESCARTADO (em vez de recusado)
  /// deixa o `ssh` pendurado sem limite prático — e o `Process.run` que resolve
  /// a `$HOME` remota, por acontecer ANTES do laço com deadline lá em [open],
  /// travava a abertura para sempre: a UI ficava eternamente em "conectando",
  /// sem nunca falhar nem entrar no ciclo de retry.
  static const int _connectTimeoutSeconds = 10;

  /// Opções de auth comuns aos execs/forward: porta custom + teto de connect +
  /// BatchMode (chave) ou aceite de host key novo (senha, via SSH_ASKPASS).
  static List<String> _authOpts({
    required int port,
    required bool usingPassword,
  }) => [
    if (port != 22) ...['-p', '$port'],
    '-o',
    'ConnectTimeout=$_connectTimeoutSeconds',
    if (usingPassword) ...[
      '-o',
      'StrictHostKeyChecking=accept-new',
    ] else ...[
      '-o',
      'BatchMode=yes',
    ],
  ];

  /// Executa um comando no host remoto pelo MESMO ssh do sistema (usado pelo
  /// bootstrap "Install server"). Retorna (exitCode, stderr).
  static Future<(int, String)> run(
    String target,
    String command, {
    List<int>? stdinBytes,
    int port = 22,
    String? password,
  }) async {
    final askpass = await _Askpass.create(password);
    try {
      final process = await Process.start('ssh', [
        ..._authOpts(port: port, usingPassword: password != null),
        target,
        command,
      ], environment: askpass?.env);
      if (stdinBytes != null) {
        process.stdin.add(stdinBytes);
      }
      await process.stdin.close();
      final stderrText = await process.stderr.transform(utf8.decoder).join();
      unawaited(process.stdout.drain<void>());
      final code = await process.exitCode;
      return (code, stderrText.trim());
    } finally {
      await askpass?.dispose();
    }
  }

  Future<void> close() async {
    _process.kill();
    await _closed.future;
    try {
      File(localSocketPath).deleteSync();
    } catch (_) {
      // já removido.
    }
  }
}

/// Injeção de senha no `ssh` do sistema via `SSH_ASKPASS` (plano 60, Wave C).
/// Escreve a senha num arquivo temporário 0600 e um helper 0700 que faz `cat`
/// dele; o ssh chama o helper quando pede a senha. `SSH_ASKPASS_REQUIRE=force`
/// (OpenSSH 8.4+) dispensa tty/DISPLAY. A senha nunca vai pra argv nem env — só
/// pro arquivo protegido, apagado em [dispose] após a autenticação.
class _Askpass {
  _Askpass._(this._pwFile, this._helper, this.env);

  final File _pwFile;
  final File _helper;
  final Map<String, String> env;

  static Future<_Askpass?> create(String? password) async {
    if (password == null || password.isEmpty) return null;
    final stamp = DateTime.now().microsecondsSinceEpoch;
    final base = Directory.systemTemp.path;
    final pwFile = File('$base/cockpit-ssh-pw-$stamp');
    await pwFile.writeAsString(password, flush: true);
    final helper = File('$base/cockpit-ssh-askpass-$stamp.sh');
    await helper.writeAsString(
      '#!/bin/sh\ncat "${pwFile.path}"\n',
      flush: true,
    );
    await Process.run('chmod', ['600', pwFile.path]);
    await Process.run('chmod', ['700', helper.path]);
    return _Askpass._(pwFile, helper, {
      'SSH_ASKPASS': helper.path,
      'SSH_ASKPASS_REQUIRE': 'force',
      // Fallback pra OpenSSH < 8.4 (que exige DISPLAY setado pra usar askpass).
      'DISPLAY': ':0',
    });
  }

  Future<void> dispose() async {
    try {
      if (_pwFile.existsSync()) _pwFile.deleteSync();
      if (_helper.existsSync()) _helper.deleteSync();
    } catch (_) {
      // já removido.
    }
  }
}

/// Erro de transporte SSH. `detail` é stderr cru do ssh — exibido
/// interpolado na frase traduzida da UI, nunca traduzido (regra de i18n).
class SshTunnelException implements Exception {
  const SshTunnelException(this.detail);
  final String detail;

  @override
  String toString() => 'SshTunnelException($detail)';
}
