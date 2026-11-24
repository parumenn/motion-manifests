// 管理ページ用パスワードのハッシュ生成ツール（対話式）
// 使い方: node hash-password.mjs
//   - パスワードは画面に表示されず、生成されたハッシュ文字列だけが表示されます。
//   - 表示された1行を k8s Secret (link-auth-secret) の LINK_ADMIN_PASSWORD_HASH に設定してください。
//   - kubectl exec で link-auth Pod 内で実行するのがおすすめです（パスワードが端末外に出ません）。
import readline from 'node:readline';
import { hashPassword } from './server.mjs';

function askHidden(question) {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = function (text) {
      // プロンプトだけ表示し、入力文字はエコーしない
      if (text.includes(question)) process.stdout.write(question);
    };
    rl.question(question, answer => {
      process.stdout.write('\n');
      rl.close();
      resolve(answer);
    });
  });
}

const pw1 = await askHidden('新しいパスワードを入力: ');
if (!pw1 || pw1.length < 8) {
  console.error('8文字以上のパスワードにしてください。');
  process.exit(1);
}
const pw2 = await askHidden('もう一度入力（確認）: ');
if (pw1 !== pw2) {
  console.error('パスワードが一致しませんでした。');
  process.exit(1);
}
console.log('\nLINK_ADMIN_PASSWORD_HASH の値（この1行を Secret に設定）:');
console.log(await hashPassword(pw1));
