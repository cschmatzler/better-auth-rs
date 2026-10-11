import { expect } from "bun:test";

import { authProfilePath } from "../../../support/profiles";
import { compatScenario } from "../../../support/scenario";

for (const profile of ["signup-synthetic-fields", "signup-synthetic-fields-custom"] as const) {
  compatScenario(
    `synthetic duplicate ${profile} retains parsed declared fields and schema filters customization`,
    async (ctx) => {
      const reset = async () => {
        expect(
          (
            await ctx.rawRequest({
              path: "/__test/signup-policy",
              method: "POST",
              json: { operation: "mode", mode: "normal" },
            })
          ).status,
        ).toBe(200);
      };
      const read = async () =>
        (await ctx.rawRequest({ path: `/__test/signup-policy/state?profile=signup-standard` }))
          .body as any;
      await reset();
      const owner = ctx.actor("owner", "signup-standard");
      const foreign = ctx.actor("foreign", "signup-standard");
      const email = ctx.uniqueEmail("synthetic-fields-owner");
      const physical = await owner.client.signUp.email({
        email,
        name: "Physical owner",
        password: "password123",
      });
      const other = await foreign.client.signUp.email({
        email: ctx.uniqueEmail("synthetic-fields-foreign"),
        name: "Foreign owner",
        password: "password123",
      });
      expect(physical.error).toBeNull();
      expect(other.error).toBeNull();
      const before = await read();
      const physicalColumns = async () => {
        const response = await ctx.rawRequest({ path: "/__test/signup-policy/synthetic-fields" });
        expect(response.status).toBe(200);
        return response.body;
      };
      const columnsBefore = await physicalColumns();
      const foreignBefore = await ctx.readUserState({ userId: other.data!.user.id });
      const outputs = [];
      for (const supplied of [true, false]) {
        await reset();
        const response = await foreign.fetch(`${authProfilePath(profile)}/sign-up/email`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            email,
            password: "password123",
            name: "Submitted fields",
            unknownApplication: "unregistered",
            ...(supplied ? { syntheticTier: " GOLD ", syntheticSecret: "submitted-private" } : {}),
          }),
        });
        expect(response.status).toBe(200);
        expect(response.headers.getSetCookie()).toEqual([]);
        const returned = await response.json();
        expect(returned.token).toBeNull();
        expect(returned.user.name).toBe("Submitted fields");
        expect(returned.user.id).not.toBe(physical.data!.user.id);
        expect(returned.user.syntheticTier).toBe(
          supplied ? (profile.endsWith("-custom") ? "custom:parsed:gold" : "parsed:gold") : null,
        );
        expect(returned.user.syntheticLocale).toBe("en");
        expect(returned.user).toHaveProperty("syntheticNote", null);
        for (const secret of ["syntheticSecret", "unknownApplication", "password"]) {
          expect(returned.user).not.toHaveProperty(secret);
        }
        const after = await read();
        expect(await physicalColumns()).toEqual(columnsBefore);
        for (const table of ["users", "accounts", "sessions", "verifications"]) {
          expect(after[table]).toEqual(before[table]);
        }
        const customization = after.events.filter((event: any) => event.stage === "synthetic-user");
        expect(customization).toHaveLength(profile.endsWith("-custom") ? 1 : 0);
        if (customization.length) {
          expect(customization[0].additionalFields).toEqual({
            ...(supplied
              ? { syntheticTier: "parsed:gold", syntheticSecret: "submitted-private" }
              : {}),
            syntheticLocale: "en",
          });
        }
        outputs.push({
          supplied,
          returned,
          customization: customization.map((event: any) => ({
            stage: event.stage,
            additionalFields: event.additionalFields,
          })),
        });
      }
      const foreignAfter = await ctx.readUserState({ userId: other.data!.user.id });
      expect(foreignAfter).toEqual(foreignBefore);
      expect((await owner.client.getSession()).data?.user.id).toBe(physical.data!.user.id);
      expect((await foreign.client.getSession()).data?.user.id).toBe(other.data!.user.id);
      return ctx.snapshot({ outputs, columnsBefore, foreignBefore, foreignAfter });
    },
    ["POST /sign-up/email", "GET /get-session"],
  );
}
