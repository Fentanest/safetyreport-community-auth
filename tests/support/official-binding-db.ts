import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
export const migration = readFileSync(new URL('../../supabase/migrations/202610061100_official_account_binding.sql', import.meta.url), 'utf8').replace(/^(begin|commit);\s*$/gm, '');
export const fixture = readFileSync(new URL('./official-binding-fixture.sql', import.meta.url), 'utf8');
export function bindingSql(body: string, beforeMigration = ''): any[] {
  const output = execFileSync('flock', ['/tmp/ci0926-db.lock', 'docker','exec','-i','supabase_db_ci0926-int',
    'psql','-X','-U','postgres','-d','postgres','-qAt','-v','ON_ERROR_STOP=1'], {
    input: `begin; set local lock_timeout='10s'; ${fixture}\n${beforeMigration}\n${migration}\n${body}\nrollback;`,
    encoding: 'utf8', timeout: 60000, stdio: ['pipe','pipe','pipe'],
  });
  return output.split('\n').filter(s => s.startsWith('{')).map(s => JSON.parse(s));
}
