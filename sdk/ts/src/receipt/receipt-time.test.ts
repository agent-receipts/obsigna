import { describe, expect, it } from "vitest";
import { parseReceiptTimeMs } from "./receipt-time.js";

describe("parseReceiptTimeMs", () => {
	it.each([
		"1970-01-01T00:00:00Z",
		"1969-12-31T23:59:59.999Z",
		"2000-02-29T12:00:00Z",
		"2026-03-01T12:30:00.5Z",
		"2026-03-01T13:30:00+01:00",
		"2026-03-01T07:30:00-05:00",
		"2026-03-01T12:30:00+23:59",
		"2026-03-01T12:30:00-00:00",
	])("matches Date for %s", (s) => {
		expect(parseReceiptTimeMs(s)).toBe(new Date(s).getTime());
	});

	it("floors long fractions", () => {
		expect(parseReceiptTimeMs("1970-01-01T00:00:00.9999999999Z")).toBe(999);
	});

	it("accepts lowercase t and z", () => {
		expect(parseReceiptTimeMs("1970-01-01t00:00:01z")).toBe(1000);
	});

	it("handles the first and last representable years", () => {
		expect(parseReceiptTimeMs("0001-01-01T00:00:00Z")).toBe(
			new Date("0001-01-01T00:00:00Z").getTime(),
		);
		expect(parseReceiptTimeMs("9999-12-31T23:59:59.999Z")).toBe(
			new Date("9999-12-31T23:59:59.999Z").getTime(),
		);
	});

	it.each([
		"",
		"2026-03-01",
		"2026-03-01T12:30:00",
		"2026-03-01 12:30:00Z",
		"2026-03-01T12:30Z",
		"2026-03-01T12:30:00+0100",
		"2026-03-01T12:30:00+01",
		"2026-03-01T12:30:00,5Z",
		"20260301T123000Z",
		"2026-02-30T12:30:00Z",
		"2026-02-29T12:30:00Z",
		"1900-02-29T12:30:00Z",
		"2026-13-01T12:30:00Z",
		"2026-00-01T12:30:00Z",
		"2026-03-00T12:30:00Z",
		"2026-03-01T24:00:00Z",
		"2026-03-01T12:60:00Z",
		"2026-03-01T12:29:60Z",
		"2026-03-01T12:30:00+24:00",
		"2026-03-01T12:30:00+01:60",
		"2026-03-01T12:30:00.Z",
		" 2026-03-01T12:30:00Z",
		"Sun, 01 Mar 2026 12:30:00 GMT",
		"２０２６-03-01T12:30:00Z",
	])("rejects %j", (s) => {
		expect(parseReceiptTimeMs(s)).toBeNull();
	});
});
