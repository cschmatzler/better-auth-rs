import { expect } from "bun:test";
import { createHmac } from "node:crypto";

import { verifyPassword } from "better-auth/crypto";
import { Cookie } from "tough-cookie";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario, type ScenarioContext } from "../../../support/scenario";

const secret = "compat-test-only-key-not-real-minimum-32chars";
const password = "Actual-Physical-Cookie-Password-301";

function record(value: unknown): Record<string, any> {
  expect(value).not.toBeNull();
  expect(typeof value).toBe("object");
  return value as Record<string, any>;
}

function cookieBytes(headers: Headers, token: string | null) {
  return headers.getSetCookie().map((raw) => {
    const equal = raw.indexOf("=");
    const end = raw.indexOf(";");
    const before = raw.slice(0, equal + 1);
    const value = raw.slice(equal + 1, end < 0 ? undefined : end);
    const after = end < 0 ? "" : raw.slice(end);
    const cookie = Cookie.parse(raw);
    expect(cookie).toBeDefined();
    expect(before + value + after).toBe(raw);

    if (!value) {
      expect(cookie!.maxAge).toBe(0);
      return { name: cookie!.key, before, value, after };
    }

    const decoded = decodeURIComponent(value);
    const dot = decoded.lastIndexOf(".");
    const plaintext = decoded.slice(0, dot);
    const signature = decoded.slice(dot + 1);
    expect(encodeURIComponent(decoded)).toBe(value);
    expect(signature).toBe(createHmac("sha256", secret).update(plaintext).digest("base64"));
    expect(Buffer.from(signature, "base64")).toHaveLength(32);

    const preference =
      cookie!.key === "physical_preference" || cookie!.key.endsWith(".dont_remember");

    if (preference) {
      expect(plaintext).toBe("true");
    } else {
      expect(token).not.toBeNull();
      expect(plaintext).toBe(token!);
    }

    return {
      name: cookie!.key,
      before,
      value: { token: value },
      after,
      plaintext: preference ? { literal: plaintext } : { token: plaintext },
      signature: { token: signature, encoding: "base64", bytes: 32 },
    };
  });
}

async function storage(ctx: ScenarioContext, id: string) {
  const r = await ctx.rawRequest({
    path: `/__test/physical-cookie/storage?userId=${encodeURIComponent(id)}`,
  });
  expect(r.status).toBe(200);

  const rows = record(r.body);

  for (const account of rows.accounts) {
    expect(account.providerId).toBe("credential");
    expect(account.userId).toBe(id);
    expect(typeof account.password).toBe("string");

    const raw = account.password;
    expect(await verifyPassword({ hash: raw, password })).toBe(true);
    expect(await verifyPassword({ hash: raw, password: "Actual-Foreign-Password-301" })).toBe(
      false,
    );

    const [salt, key] = raw.split(":");
    expect(salt).toMatch(/^[a-f0-9]{32}$/);
    expect(key).toMatch(/^[a-f0-9]{128}$/);

    account.password = {
      token: raw,
      salt: { token: salt, length: 32 },
      derivedKey: { token: key, length: 128 },
      encoding: "hex-lower",
    };
  }

  return rows;
}

for (const mode of [
  "default",
  "attributes",
  "secure",
  "none",
  "short",
  "legacy",
  "legacy-alias",
  "secure-prefix",
  "https-default",
  "https-disabled",
  "secure-custom",
  "dynamic-https",
  "dynamic-http",
  "dynamic-auto",
] as const) {
  compatScenario(
    `physical session ${mode} preserves full signed token preference bytes through signup signin restore corruption rotation and logout`,
    async (ctx) => {
      const profile = `physical-cookie-${mode}` as const;
      const path = authProfilePath(profile);
      const owner = ctx.actor("owner", profile).client;
      const foreign = ctx.actor("foreign", profile).client;
      const guest = ctx.actor("guest", profile).client;
      const email = ctx.uniqueEmail(`cookie-${mode}`);
      let issuedHeaders: Headers | undefined;
      const created = await owner.signUp.email({
        email,
        name: "Actual physical cookie owner",
        password,
        fetchOptions: {
          onSuccess({ response }) {
            issuedHeaders = new Headers(response.headers);
          },
        },
      });
      expect(created.error).toBeNull();
      expect(issuedHeaders).toBeDefined();

      const first = record(created.data);
      const signupCookies = cookieBytes(issuedHeaders!, first.token);
      expect(signupCookies).toHaveLength(1);

      const prefixed = [
        "secure-prefix",
        "https-default",
        "secure-custom",
        "dynamic-https",
      ].includes(mode);
      const expectedTokenName =
        mode === "secure-custom"
          ? "__Secure-configured_session"
          : prefixed
            ? "__Secure-better-auth.session_token"
            : mode === "attributes"
              ? "physical_session"
              : mode === "legacy"
                ? "customsession"
                : mode === "legacy-alias"
                  ? "some.alias"
                  : "better-auth.session_token";
      const expectedPreferenceName =
        mode === "attributes"
          ? "physical_preference"
          : mode === "secure-custom"
            ? "__Secure-policy.dont_remember"
            : `${prefixed ? "__Secure-" : ""}better-auth.dont_remember`;
      expect(signupCookies[0]!.name).toBe(expectedTokenName);

      const other = await foreign.signUp.email({
        email: ctx.uniqueEmail(`foreign-${mode}`),
        name: "Actual physical foreign owner",
        password,
      });
      expect(other.error).toBeNull();
      expect(other.data!.token).toBeString();

      const foreignRead = await foreign.getSession();
      expect(foreignRead.error).toBeNull();
      expect(foreignRead.data!.user.id).toBe(other.data!.user.id);
      expect(foreignRead.data!.session.token).toBe(other.data!.token!);
      expect(foreignRead.data!.user.id).not.toBe(first.user.id);

      const foreignBefore = await storage(ctx, other.data!.user.id);
      const before = await storage(ctx, first.user.id);
      expect(before.user).toHaveLength(1);
      expect(before.accounts).toHaveLength(1);
      expect(before.sessions).toHaveLength(1);
      expect(before.sessions[0].token).toBe(first.token);

      const signupCookie = Cookie.parse(issuedHeaders!.getSetCookie()[0]!)!;
      expect(signupCookie.maxAge).toBe(mode === "short" ? 60 : 604800);
      expect(signupCookie.path).toBe(
        mode === "attributes" || mode === "secure-custom" ? path : "/",
      );
      expect(signupCookie.domain).toBe(mode === "attributes" ? "localhost" : null);
      expect(signupCookie.httpOnly).toBe(mode !== "attributes");
      expect(signupCookie.secure).toBe(mode === "secure" || prefixed);
      expect(signupCookie.sameSite).toBe(
        mode === "attributes" ? "strict" : mode === "none" ? "none" : "lax",
      );

      const restored = await owner.getSession();
      expect(restored.error).toBeNull();
      expect(restored.data!.session.token).toBe(first.token);

      const guestRead = await guest.getSession();
      expect(guestRead.data).toBeNull();

      const raw = issuedHeaders!.getSetCookie()[0]!.split(";")[0]!;
      const decoded = decodeURIComponent(raw.slice(raw.indexOf("=") + 1));
      const dot = decoded.lastIndexOf(".");
      const badSignature = decoded.slice(dot + 1);
      const corrupt = `${expectedTokenName}=${encodeURIComponent(decoded.slice(0, dot + 1) + (badSignature[0] === "A" ? "B" : "A") + badSignature.slice(1))}`;
      const rejected = await ctx.rawRequest({
        path: path + "/get-session",
        actor: "corrupt-proof",
        headers: { cookie: corrupt },
      });
      expect(rejected.status).toBe(200);
      expect(rejected.body).toBeNull();

      const protectedState = await storage(ctx, first.user.id);
      expect(protectedState).toEqual(before);
      expect(await storage(ctx, other.data!.user.id)).toEqual(foreignBefore);

      let transientHeaders: Headers | undefined;
      const transient = await owner.signIn.email({
        email,
        password,
        rememberMe: false,
        fetchOptions: {
          onSuccess({ response }) {
            transientHeaders = new Headers(response.headers);
          },
        },
      });
      expect(transient.error).toBeNull();
      expect(transientHeaders).toBeDefined();

      const transientData = record(transient.data);
      expect(transientData.token).not.toBe(first.token);

      const transientCookies = cookieBytes(transientHeaders!, transientData.token);
      expect(transientCookies.map((row) => row.name)).toEqual([
        expectedTokenName,
        expectedPreferenceName,
      ]);
      expect(Cookie.parse(transientHeaders!.getSetCookie()[0]!)!.maxAge).toBeNull();
      expect(Cookie.parse(transientHeaders!.getSetCookie()[0]!)!.expires).toBe("Infinity");

      const preferenceAge = Cookie.parse(transientHeaders!.getSetCookie()[1]!)!.maxAge;

      if (mode === "attributes") {
        expect(preferenceAge).toBe(121);
      } else {
        expect(preferenceAge).toBeNull();
      }

      const transientRead = await owner.getSession();
      expect(transientRead.data!.session.token).toBe(transientData.token);

      const transientState = await storage(ctx, first.user.id);
      expect(transientState.sessions).toHaveLength(2);

      let durableHeaders: Headers | undefined;
      const durable = await owner.signIn.email({
        email,
        password,
        rememberMe: true,
        fetchOptions: {
          onSuccess({ response }) {
            durableHeaders = new Headers(response.headers);
          },
        },
      });
      expect(durable.error).toBeNull();
      expect(durableHeaders).toBeDefined();

      const durableData = record(durable.data);
      expect(durableData.token).not.toBe(transientData.token);

      const durableCookies = cookieBytes(durableHeaders!, durableData.token);
      expect(durableCookies).toHaveLength(1);
      expect(Cookie.parse(durableHeaders!.getSetCookie()[0]!)!.maxAge).toBe(
        mode === "short" ? 60 : 604800,
      );

      const durableRead = await owner.getSession();
      expect(durableRead.data!.session.token).toBe(durableData.token);

      const durableState = await storage(ctx, first.user.id);
      expect(durableState.sessions).toHaveLength(3);

      let clearedHeaders: Headers | undefined;
      const signedOut = await owner.signOut({
        fetchOptions: {
          onSuccess({ response }) {
            clearedHeaders = new Headers(response.headers);
          },
        },
      });
      expect(signedOut.error).toBeNull();
      expect(clearedHeaders).toBeDefined();

      const cleared = cookieBytes(clearedHeaders!, null);
      expect(cleared.map((row) => row.name)).toContain(expectedTokenName);
      expect(cleared.map((row) => row.name)).toContain(expectedPreferenceName);

      const empty = await owner.getSession();
      expect(empty.data).toBeNull();

      const after = await storage(ctx, first.user.id);
      expect(after.user).toEqual(before.user);
      expect(after.accounts).toEqual(before.accounts);
      expect(after.sessions).toHaveLength(2);
      expect(
        after.sessions.some((row: Record<string, any>) => row.token === durableData.token),
      ).toBe(false);
      expect(after.sessions.find((row: Record<string, any>) => row.token === first.token)).toEqual(
        before.sessions[0],
      );
      expect(await storage(ctx, other.data!.user.id)).toEqual(foreignBefore);

      return {
        mode,
        created,
        signupCookies,
        other,
        foreignRead,
        foreignBefore,
        before,
        restored,
        guestRead,
        rejected,
        protectedState,
        transient,
        transientCookies,
        transientRead,
        transientState,
        durable,
        durableCookies,
        durableRead,
        durableState,
        signedOut,
        cleared,
        empty,
        after,
      };
    },
    ["POST /sign-up/email", "POST /sign-in/email", "POST /sign-out"],
  );
}
