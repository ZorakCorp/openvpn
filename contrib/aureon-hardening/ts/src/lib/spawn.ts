import { spawnSync } from "node:child_process";

export function spawnCmd(
  cmd: string[],
  timeoutMs: number,
  options?: { shell?: boolean }
): { code: number; stdout: string; stderr: string } {
  try {
    const r = spawnSync(cmd[0]!, cmd.slice(1), {
      encoding: "utf-8",
      timeout: timeoutMs,
      shell: options?.shell ?? false,
      windowsHide: true,
    });
    return {
      code: r.status ?? (r.error ? -2 : -1),
      stdout: (r.stdout as string) ?? "",
      stderr: (r.stderr as string) ?? "",
    };
  } catch (e) {
    return { code: -2, stdout: "", stderr: String(e) };
  }
}
