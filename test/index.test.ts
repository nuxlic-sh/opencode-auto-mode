import { describe, expect, test } from "bun:test"

import autoMode from "../src/index.ts"

type MockState = {
  promptCalls: number
  reviewerRequests: string[]
}

function makeShell() {
  return (() => {
    const promise = Promise.resolve({
      exitCode: 1,
      text: () => "",
    }) as Promise<{ exitCode: number; text(): string }> & {
      cwd(path: string): unknown
      quiet(): unknown
      nothrow(): unknown
    }
    promise.cwd = () => promise
    promise.quiet = () => promise
    promise.nothrow = () => promise
    return promise
  }) as never
}

async function makeHooks(reviewerText = "ALLOW: authorized test operation") {
  const state: MockState = { promptCalls: 0, reviewerRequests: [] }
  const client = {
    app: {
      log: async () => ({ data: true }),
    },
    tui: {
      showToast: async () => ({ data: true }),
    },
    session: {
      messages: async () => ({ data: [] }),
      create: async () => ({ data: { id: "review-session" } }),
      prompt: async (request: { body?: { parts?: Array<{ text?: string }> } }) => {
        state.promptCalls += 1
        state.reviewerRequests.push(request.body?.parts?.[0]?.text ?? "")
        return {
          data: {
            parts: [{ type: "text", text: reviewerText }],
          },
        }
      },
      abort: async () => ({ data: true }),
      delete: async () => ({ data: true }),
    },
    postSessionIdPermissionsPermissionId: async () => ({ data: true }),
  }
  const hooks = await autoMode(
    {
      client,
      directory: "/workspace/project",
      worktree: "/workspace/project",
      project: { id: "project" },
      serverUrl: new URL("http://localhost:4096"),
      $: makeShell(),
    } as never,
    { enabled: true, model: "openai/test-model" },
  )
  return { hooks, state }
}

async function executeBefore(
  hooks: Awaited<ReturnType<typeof autoMode>>,
  tool: string,
  args: Record<string, unknown>,
) {
  const hook = hooks["tool.execute.before"]
  if (!hook) throw new Error("tool.execute.before hook is missing")
  return hook({ tool, sessionID: "session", callID: "call" }, { args })
}

describe("configuration", () => {
  test("replaces native asks while preserving explicit denies", async () => {
    const { hooks } = await makeHooks()
    const config = {
      permission: {
        "*": "ask",
        edit: { "*": "ask", locked: "deny" },
      },
      agent: {
        custom: {
          permission: { bash: "ask", edit: "deny" },
        },
      },
    } as never

    await hooks.config?.(config)

    expect(config).toMatchObject({
      permission: {
        "*": "allow",
        edit: { "*": "allow", locked: "deny" },
      },
      agent: {
        custom: {
          permission: { "*": "allow", bash: "allow", edit: "deny" },
        },
        "auto-reviewer": {
          hidden: true,
          permission: { "*": "deny" },
          model: "openai/test-model",
        },
      },
    })
  })
})

describe("pre-execution review", () => {
  test("statically permits a single safe command", async () => {
    const { hooks, state } = await makeHooks()

    await executeBefore(hooks, "bash", { command: "date" })

    expect(state.promptCalls).toBe(0)
  })

  test("hard-blocks privilege escalation without calling the model", async () => {
    const { hooks, state } = await makeHooks()

    await expect(executeBefore(hooks, "bash", { command: "sudo --version" })).rejects.toThrow(
      "privilege escalation",
    )
    expect(state.promptCalls).toBe(0)
  })

  test("does not statically allow a newline-appended command", async () => {
    const { hooks, state } = await makeHooks("BLOCK: shell control operator requires rejection")

    await expect(executeBefore(hooks, "bash", { command: "ls\nprintf unsafe" })).rejects.toThrow(
      "Auto-reviewer blocked bash",
    )
    expect(state.promptCalls).toBe(1)
  })

  test("does not statically allow an OR-appended command", async () => {
    const { hooks, state } = await makeHooks("BLOCK: shell control operator requires rejection")

    await expect(executeBefore(hooks, "bash", { command: "ls||printf unsafe" })).rejects.toThrow(
      "Auto-reviewer blocked bash",
    )
    expect(state.promptCalls).toBe(1)
  })

  test("does not statically allow a background-appended command", async () => {
    const { hooks, state } = await makeHooks("BLOCK: background command requires rejection")

    await expect(executeBefore(hooks, "bash", { command: "ls&printf unsafe" })).rejects.toThrow(
      "Auto-reviewer blocked bash",
    )
    expect(state.promptCalls).toBe(1)
  })

  test("rejects an ALLOW decision embedded in a multiline response", async () => {
    const { hooks, state } = await makeHooks("Commentary before decision\nALLOW: unsafe response shape")

    await expect(executeBefore(hooks, "bash", { command: "printf test" })).rejects.toThrow(
      "Auto-reviewer unavailable",
    )
    expect(state.promptCalls).toBe(1)
  })

  test.each(["\v", "\f", "\u0085", "\u2028", "\u2029"])(
    "rejects contradictory decisions separated by %p",
    async (separator) => {
      const { hooks, state } = await makeHooks(`ALLOW: looks safe${separator}BLOCK: actually unsafe`)

      await expect(executeBefore(hooks, "bash", { command: "printf test" })).rejects.toThrow(
        "Auto-reviewer unavailable",
      )
      expect(state.promptCalls).toBe(1)
    },
  )

  test.each(["git branch -a --unset-upstream main", "git stash list --output=/outside/project/result"])(
    "reviews Git commands with potentially mutating options: %s",
    async (command) => {
      const { hooks, state } = await makeHooks("BLOCK: Git option is not statically safe")

      await expect(executeBefore(hooks, "bash", { command })).rejects.toThrow("Auto-reviewer blocked bash")
      expect(state.promptCalls).toBe(1)
    },
  )

  test("reviews external reads instead of statically allowing them", async () => {
    const { hooks, state } = await makeHooks("ALLOW: explicitly authorized external read")

    await executeBefore(hooks, "read", { filePath: "/outside/project/file.txt" })

    expect(state.promptCalls).toBe(1)
  })

  test("reviews remote and subagent tools", async () => {
    const { hooks, state } = await makeHooks()

    await executeBefore(hooks, "task", { description: "test", prompt: "sensitive instructions" })
    await executeBefore(hooks, "list_mcp_resources", { server: "remote" })

    expect(state.promptCalls).toBe(2)
  })

  test("redacts secrets embedded in URLs before review", async () => {
    const { hooks, state } = await makeHooks()

    await executeBefore(hooks, "webfetch", {
      url: "https://example.test/path?token=TOP_SECRET_SENTINEL",
      description: "TOP_SECRET_SENTINEL",
    })

    expect(state.promptCalls).toBe(1)
    expect(state.reviewerRequests[0]).toContain("https://example.test/path")
    expect(state.reviewerRequests[0]).not.toContain("TOP_SECRET_SENTINEL")
  })
})
