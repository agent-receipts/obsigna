// Deterministic, offline OpenAI-compatible model server for the demo.
//
// WHY A MOCK MODEL: this demo proves the integrity path
//   opencode -> @obsigna/opencode-plugin -> obsigna-daemon -> signed checkpoint
// not the intelligence of any LLM. The model sits OUTSIDE the trust boundary
// being demonstrated: whoever (or whatever) decides the tool calls, the receipt
// and checkpoint path is identical. Stubbing it keeps the demo reproducible,
// free, and network-free at run time — opencode itself, the plugin, the daemon,
// the Ed25519 signing, the git anchor, and `obsigna verify` are all the real,
// shipped code. To run against a real model instead, see the README ("Run it
// against a real model").
//
// The server drives opencode through MOCK_TOOLCALLS native `bash` tool calls
// (one per turn), then ends with a short final message. It decides what to do
// by counting how many tool results are already in the conversation.

import http from "node:http";

const PORT = Number(process.env.MOCK_PORT || 11434);
const N = Number(process.env.MOCK_TOOLCALLS || 5);

function sse(res, obj) {
	res.write(`data: ${JSON.stringify(obj)}\n\n`);
}

const server = http.createServer((req, res) => {
	let body = "";
	req.on("data", (c) => (body += c));
	req.on("end", () => {
		if (!req.url.includes("/chat/completions")) {
			res.writeHead(200, { "content-type": "application/json" });
			res.end(JSON.stringify({ object: "list", data: [{ id: "mock", object: "model" }] }));
			return;
		}
		let parsed = {};
		try {
			parsed = JSON.parse(body);
		} catch {}
		const messages = parsed.messages || [];
		const toolResults = messages.filter((m) => m.role === "tool").length;

		res.writeHead(200, {
			"content-type": "text/event-stream",
			"cache-control": "no-cache",
			connection: "keep-alive",
		});
		const base = {
			id: "chatcmpl-mock",
			object: "chat.completion.chunk",
			created: Math.floor(Date.now() / 1000),
			model: parsed.model || "mock",
		};

		if (toolResults < N) {
			const n = toolResults + 1;
			const args = JSON.stringify({
				command: `echo demo-receipt-${n}`,
				description: `demo step ${n}`,
			});
			sse(res, { ...base, choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }] });
			sse(res, {
				...base,
				choices: [
					{
						index: 0,
						delta: { tool_calls: [{ index: 0, id: `call_${n}`, type: "function", function: { name: "bash", arguments: "" } }] },
						finish_reason: null,
					},
				],
			});
			sse(res, {
				...base,
				choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: args } }] }, finish_reason: null }],
			});
			sse(res, {
				...base,
				choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }],
				usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
			});
		} else {
			sse(res, {
				...base,
				choices: [{ index: 0, delta: { role: "assistant", content: `Ran ${N} demo commands.` }, finish_reason: null }],
			});
			sse(res, {
				...base,
				choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
				usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
			});
		}
		res.write("data: [DONE]\n\n");
		res.end();
	});
});

server.listen(PORT, "127.0.0.1", () => {
	process.stderr.write(`[mock-model] listening on http://127.0.0.1:${PORT} (driving ${N} tool calls)\n`);
});
