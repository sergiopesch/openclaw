import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

import {
  findMatchingSystemdUserUnit,
  parseSystemdShow,
  readSystemdServiceExecStart,
  resolveSystemdUserUnitPath,
} from "./systemd.js";

describe("systemd runtime parsing", () => {
  it("parses active state details", () => {
    const output = [
      "ActiveState=inactive",
      "SubState=dead",
      "MainPID=0",
      "ExecMainStatus=2",
      "ExecMainCode=exited",
    ].join("\n");
    expect(parseSystemdShow(output)).toEqual({
      activeState: "inactive",
      subState: "dead",
      execMainStatus: 2,
      execMainCode: "exited",
    });
  });
});

describe("resolveSystemdUserUnitPath", () => {
  it("uses default service name when OPENCLAW_PROFILE is default", () => {
    const env = { HOME: "/home/test", OPENCLAW_PROFILE: "default" };
    expect(resolveSystemdUserUnitPath(env)).toBe(
      "/home/test/.config/systemd/user/openclaw-gateway.service",
    );
  });

  it("uses default service name when OPENCLAW_PROFILE is unset", () => {
    const env = { HOME: "/home/test" };
    expect(resolveSystemdUserUnitPath(env)).toBe(
      "/home/test/.config/systemd/user/openclaw-gateway.service",
    );
  });

  it("uses profile-specific service name when OPENCLAW_PROFILE is set to a custom value", () => {
    const env = { HOME: "/home/test", OPENCLAW_PROFILE: "jbphoenix" };
    expect(resolveSystemdUserUnitPath(env)).toBe(
      "/home/test/.config/systemd/user/openclaw-gateway-jbphoenix.service",
    );
  });

  it("prefers OPENCLAW_SYSTEMD_UNIT over OPENCLAW_PROFILE", () => {
    const env = {
      HOME: "/home/test",
      OPENCLAW_PROFILE: "jbphoenix",
      OPENCLAW_SYSTEMD_UNIT: "custom-unit",
    };
    expect(resolveSystemdUserUnitPath(env)).toBe(
      "/home/test/.config/systemd/user/custom-unit.service",
    );
  });

  it("handles OPENCLAW_SYSTEMD_UNIT with .service suffix", () => {
    const env = {
      HOME: "/home/test",
      OPENCLAW_SYSTEMD_UNIT: "custom-unit.service",
    };
    expect(resolveSystemdUserUnitPath(env)).toBe(
      "/home/test/.config/systemd/user/custom-unit.service",
    );
  });

  it("trims whitespace from OPENCLAW_SYSTEMD_UNIT", () => {
    const env = {
      HOME: "/home/test",
      OPENCLAW_SYSTEMD_UNIT: "  custom-unit  ",
    };
    expect(resolveSystemdUserUnitPath(env)).toBe(
      "/home/test/.config/systemd/user/custom-unit.service",
    );
  });

  it("handles case-insensitive 'Default' profile", () => {
    const env = { HOME: "/home/test", OPENCLAW_PROFILE: "Default" };
    expect(resolveSystemdUserUnitPath(env)).toBe(
      "/home/test/.config/systemd/user/openclaw-gateway.service",
    );
  });

  it("handles case-insensitive 'DEFAULT' profile", () => {
    const env = { HOME: "/home/test", OPENCLAW_PROFILE: "DEFAULT" };
    expect(resolveSystemdUserUnitPath(env)).toBe(
      "/home/test/.config/systemd/user/openclaw-gateway.service",
    );
  });

  it("trims whitespace from OPENCLAW_PROFILE", () => {
    const env = { HOME: "/home/test", OPENCLAW_PROFILE: "  myprofile  " };
    expect(resolveSystemdUserUnitPath(env)).toBe(
      "/home/test/.config/systemd/user/openclaw-gateway-myprofile.service",
    );
  });
});

describe("systemd unit discovery", () => {
  it("finds a generic gateway unit when it matches the profiled state dir", async () => {
    const home = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-systemd-"));
    const userDir = path.join(home, ".config", "systemd", "user");
    await fs.mkdir(userDir, { recursive: true });
    const stateDir = path.join(home, ".openclaw-laptop-local");
    await fs.writeFile(
      path.join(userDir, "openclaw-gateway.service"),
      [
        "[Service]",
        "ExecStart=/usr/bin/node /opt/openclaw gateway --port 18789",
        `Environment=OPENCLAW_STATE_DIR=${stateDir}`,
        `Environment=OPENCLAW_CONFIG_PATH=${path.join(stateDir, "openclaw.json")}`,
        "Environment=OPENCLAW_SERVICE_MARKER=openclaw",
        "Environment=OPENCLAW_SERVICE_KIND=gateway",
        "",
      ].join("\n"),
      "utf8",
    );

    const env = {
      HOME: home,
      OPENCLAW_PROFILE: "laptop-local",
      OPENCLAW_STATE_DIR: stateDir,
      OPENCLAW_CONFIG_PATH: path.join(stateDir, "openclaw.json"),
    };

    const match = await findMatchingSystemdUserUnit(env);
    expect(match?.name).toBe("openclaw-gateway");

    const command = await readSystemdServiceExecStart(env);
    expect(command?.sourcePath).toBe(path.join(userDir, "openclaw-gateway.service"));
    expect(command?.environment?.OPENCLAW_STATE_DIR).toBe(stateDir);
  });
});
