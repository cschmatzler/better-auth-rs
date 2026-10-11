import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

for (const profile of ["signup-synthetic-id", "signup-synthetic-id-custom"] as const) {
  compatScenario(
    `synthetic duplicate ${profile} uses application IDs before customization and preserves physical principals`,
    async (ctx) => {
      const control = async (mode: string) => {
        const response = await ctx.rawRequest({
          path: "/__test/signup-policy",
          method: "POST",
          json: { operation: "mode", mode },
        });
        expect(response.status).toBe(200);
      };
      const read = async () =>
        (await ctx.rawRequest({ path: `/__test/signup-policy/state?profile=${profile}` }))
          .body as any;
      await control("normal");
      const owner = ctx.actor("owner", "signup-standard");
      const foreign = ctx.actor("foreign", "signup-standard");
      const email = ctx.uniqueEmail("synthetic-id-owner");
      const physical = await owner.client.signUp.email({
        email,
        name: "Physical owner",
        password: "password123",
      });
      const other = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("synthetic-id-foreign"),
        name: "Foreign owner",
        password: "password123",
      });
      expect(physical.error).toBeNull();
      expect(other.error).toBeNull();
      const before = await read();
      const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
      await control("normal");
      const response = await foreign.fetch(`${authProfilePath(profile)}/sign-up/email`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, name: "Submitted name", password: "password123" }),
      });
      expect(response.status).toBe(200);
      expect(response.headers.getSetCookie()).toEqual([]);
      const returned = await response.json();
      expect(returned.token).toBeNull();
      expect(returned.user.id).toBe("synthetic_application_1");
      expect(returned.user.id).not.toBe(physical.data!.user.id);
      expect(returned.user.name).toBe("Submitted name");
      const after = await read();
      for (const table of ["users", "accounts", "sessions", "verifications"]) {
        expect(after[table]).toEqual(before[table]);
      }
      const generators = after.events.filter((event: any) => event.stage === "id-generation");
      expect(generators).toEqual([{ stage: "id-generation", model: "user", size: null }]);
      const customization = after.events.filter((event: any) => event.stage === "synthetic-user");
      expect(customization).toHaveLength(profile.endsWith("-custom") ? 1 : 0);
      if (customization.length) expect(customization[0].id).toBe("synthetic_application_1");
      await control("id-error");
      const failed = await foreign.fetch(`${authProfilePath(profile)}/sign-up/email`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, name: "Submitted name", password: "password123" }),
      });
      expect(failed.status).toBe(500);
      expect(failed.headers.getSetCookie()).toEqual([]);
      const rejected = await read();
      expect(rejected.events.filter((event: any) => event.stage === "id-generation")).toEqual(
        generators,
      );
      expect(rejected.events.filter((event: any) => event.stage === "synthetic-user")).toEqual([]);
      for (const table of ["users", "accounts", "sessions", "verifications"]) {
        expect(rejected[table]).toEqual(before[table]);
      }
      const foreignAfter = await ctx.readUserState({ userId: other.data!.user.id });
      expect(foreignAfter).toEqual(foreignBefore);
      expect((await owner.client.getSession()).data?.user.id).toBe(physical.data!.user.id);
      expect((await foreign.client.getSession()).data?.user.id).toBe(other.data!.user.id);
      return ctx.snapshot({
        returned,
        generators,
        customization: customization.map((event: any) => ({
          stage: event.stage,
          id: event.id,
          additionalFields: event.additionalFields,
        })),
        failure: failed.status,
        foreignBefore,
        foreignAfter,
      });
    },
    ["POST /sign-up/email", "GET /get-session"],
  );
}
