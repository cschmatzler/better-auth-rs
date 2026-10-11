/** Application options exercised through the actual pinned signup/password routes. */

import type { Database } from "bun:sqlite";

import { type BetterAuthOptions, betterAuth } from "better-auth";
import { APIError } from "better-auth/api";
import { hashPassword, verifyPassword } from "better-auth/crypto";
import { emailOTP, phoneNumber, username } from "better-auth/plugins";

export function createSignupPolicyFixture(database: Database, shared: BetterAuthOptions) {
  for (const column of [
    "synthetic_tier",
    "synthetic_secret",
    "synthetic_locale",
    "synthetic_note",
  ]) {
    database.run(`ALTER TABLE "user" ADD COLUMN ${column} TEXT`);
  }
  const events: Record<string, unknown>[] = [];
  let mode = "normal";
  let releaseExisting: (() => void) | undefined;
  const profiles = new Map<string, ReturnType<typeof betterAuth>>();

  for (const name of [
    "signup-standard",
    "signup-disabled",
    "signup-password-disabled",
    "signup-no-auto",
    "signup-required",
    "signup-custom",
    "signup-synthetic-fields",
    "signup-synthetic-fields-custom",
    "signup-synthetic-id",
    "signup-synthetic-id-custom",
    "signup-policy",
    "signup-zero-policy",
    "signup-username",
    "signup-username-limits",
    "signup-username-unicode",
    "signup-username-implicit",
    "signup-username-display-pre",
    "signup-username-display-post",
    "signup-username-throw",
    "signup-username-required",
    "signup-username-readonly",
    "signup-username-preserve",
    "signup-username-pre",
    "signup-username-post",
    "signup-username-immutable",
    "signup-username-display-disabled",
    "signup-otp",
    "signup-background",
  ]) {
    const basePath = `/__test/profiles/${name}/api/auth`;
    const requireEmailVerification =
      name === "signup-required" || name === "signup-otp" || name === "signup-username-required";
    const autoSignIn = ![
      "signup-no-auto",
      "signup-custom",
      "signup-synthetic-fields",
      "signup-synthetic-fields-custom",
      "signup-synthetic-id",
      "signup-synthetic-id-custom",
      "signup-username",
      "signup-background",
    ].includes(name);
    const instance = betterAuth({
      ...shared,
      database,
      basePath,
      ...(name.startsWith("signup-synthetic-fields")
        ? {
            user: {
              ...shared.user,
              additionalFields: {
                syntheticTier: {
                  type: "string" as const,
                  fieldName: "synthetic_tier",
                  validator: {
                    input: {
                      "~standard": {
                        version: 1 as const,
                        vendor: "synthetic-fixture",
                        validate(value: unknown) {
                          return typeof value === "string"
                            ? { value: `parsed:${value.trim().toLowerCase()}` }
                            : { issues: [{ message: "tier must be a string" }] };
                        },
                      },
                    },
                  },
                },
                syntheticSecret: {
                  type: "string" as const,
                  fieldName: "synthetic_secret",
                  returned: false,
                },
                syntheticLocale: {
                  type: "string" as const,
                  fieldName: "synthetic_locale",
                  defaultValue: "en",
                },
                syntheticNote: { type: "string" as const, fieldName: "synthetic_note" },
              },
            },
          }
        : {}),
      databaseHooks: {
        user: {
          create: {
            before: async (_user, context) => {
              if (name.startsWith("signup-username-")) {
                events.push({
                  stage: "username-hook",
                  request: context?.request
                    ? {
                        method: context.request.method,
                        path: context.path,
                        marker: context.request.headers.get("x-test-policy-marker"),
                        contentType: context.request.headers.get("content-type"),
                      }
                    : null,
                });
              }

              if (mode === "user-forbidden") {
                events.push({ stage: "user-create-denied" });
                throw new APIError("FORBIDDEN", {
                  code: "USER_CREATION_DENIED",
                  message: "Configured user creation denied",
                });
              }

              if (mode === "user-cancel") {
                events.push({ stage: "user-create-cancelled" });
                return false;
              }

              if (mode === "user-error") {
                events.push({ stage: "user-create-error" });
                throw new Error("Actual configured user creation failed");
              }
            },
          },
        },
      },
      plugins: [
        ...(name.startsWith("signup-username")
          ? [
              username({
                ...(name === "signup-username-limits"
                  ? { minUsernameLength: 2, maxUsernameLength: 5 }
                  : {}),
                ...(name === "signup-username-preserve" ? { usernameNormalization: false } : {}),
                ...([
                  "signup-username-pre",
                  "signup-username-post",
                  "signup-username-implicit",
                ].includes(name)
                  ? {
                      usernameNormalization: (value: string) => {
                        events.push({ stage: "username", callback: "normalize", value });
                        return value.trim().replaceAll("-", "_").toLowerCase();
                      },
                      ...(name === "signup-username-implicit"
                        ? {}
                        : {
                            validationOrder: {
                              username:
                                name === "signup-username-pre"
                                  ? ("pre-normalization" as const)
                                  : ("post-normalization" as const),
                            },
                          }),
                    }
                  : {}),
                ...(name === "signup-username-unicode"
                  ? {
                      minUsernameLength: 2,
                      maxUsernameLength: 4,
                      async usernameValidator(value: string) {
                        events.push({ stage: "username", callback: "validate", value });
                        return /^[\p{L}😀]+$/u.test(value);
                      },
                    }
                  : {}),
                ...(name === "signup-username-throw"
                  ? {
                      async usernameValidator(value: string) {
                        events.push({ stage: "username", callback: "validate", value });
                        if (value === "explode") {
                          throw new Error("Actual username validator failed");
                        }
                        return true;
                      },
                    }
                  : {}),
                ...(["signup-username-display-pre", "signup-username-display-post"].includes(name)
                  ? {
                      displayUsernameNormalization: (value: string) => {
                        events.push({ stage: "username", callback: "display-normalize", value });
                        return value.trim().toUpperCase();
                      },
                      async displayUsernameValidator(value: string) {
                        events.push({ stage: "username", callback: "display-validate", value });
                        return /^[A-Z ]+$/.test(value);
                      },
                      validationOrder: {
                        displayUsername:
                          name === "signup-username-display-pre"
                            ? ("pre-normalization" as const)
                            : ("post-normalization" as const),
                      },
                    }
                  : {}),
                ...(name === "signup-username-immutable" ? { immutableUsername: true } : {}),
                ...(name === "signup-username-display-disabled" ? { displayUsername: false } : {}),
              }),
            ].map((plugin) => {
              if (name === "signup-username-readonly") {
                plugin.schema.user.fields.username.input = false;
              }
              return plugin;
            })
          : []),
        ...(name === "signup-otp" || name.startsWith("signup-username-")
          ? [
              emailOTP({
                overrideDefaultEmailVerification: name === "signup-otp",
                async sendVerificationOTP(delivery) {
                  events.push({ stage: "otp", ...delivery });
                },
              }),
            ]
          : []),
        ...(name.startsWith("signup-username-")
          ? [
              phoneNumber({
                async sendOTP(delivery) {
                  events.push({ stage: "phone-otp", ...delivery });
                },
                signUpOnVerification: {
                  getTempEmail: (phone: string) => `${phone}@phone.fixture.test`,
                },
              }),
            ]
          : []),
      ],
      advanced: {
        ...shared.advanced,
        ...(name.startsWith("signup-synthetic-id")
          ? {
              database: {
                generateId({ model, size }) {
                  events.push({ stage: "id-generation", model, size: size ?? null });
                  if (mode === "id-error") throw new Error("application ID failed");
                  return "synthetic_application_1";
                },
              },
            }
          : {}),
        ...(name === "signup-background"
          ? {
              backgroundTasks: {
                handler(completion: Promise<unknown>) {
                  events.push({ stage: "background-register" });
                  void completion;
                  if (mode === "background-error") {
                    throw new Error("Actual background observer failed");
                  }
                },
              },
            }
          : {}),
      },
      emailVerification:
        name === "signup-otp"
          ? { sendOnSignUp: true, autoSignInAfterVerification: false }
          : {
              ...shared.emailVerification,
              async sendVerificationEmail({ user, url, token }) {
                events.push({ stage: "verification-email", user, url, token });
              },
            },
      emailAndPassword: {
        ...shared.emailAndPassword,
        enabled: name !== "signup-password-disabled",
        disableSignUp: name === "signup-disabled",
        autoSignIn,
        requireEmailVerification,
        minPasswordLength: name === "signup-zero-policy" ? 0 : name === "signup-policy" ? 10 : 8,
        maxPasswordLength: name === "signup-zero-policy" ? 0 : name === "signup-policy" ? 20 : 128,
        resetPasswordTokenExpiresIn:
          name === "signup-zero-policy" ? 0 : name === "signup-policy" ? 90 : 3600,
        revokeSessionsOnPasswordReset: name === "signup-policy",
        password: {
          async hash(password) {
            events.push({ stage: "hash-enter", password });
            const hash = await hashPassword(password);
            events.push({ stage: "hash-result", password, hash });

            if (mode === "hash-error") {
              throw new Error("Actual configured hash failed");
            }

            if (mode === "hash-api") {
              throw new APIError("FORBIDDEN", {
                code: "HASH_REJECTED",
                message: "Configured hash rejected",
              });
            }

            return hash;
          },
          async verify({ hash, password }) {
            events.push({ stage: "verify-enter", hash, password });
            const valid = await verifyPassword({ hash, password });
            events.push({ stage: "verify-result", hash, password, valid });

            if (mode === "verify-error") {
              throw new Error("Actual configured verifier failed");
            }

            if (mode === "verify-api") {
              throw new APIError("FORBIDDEN", {
                code: "VERIFY_REJECTED",
                message: "Configured verifier rejected",
              });
            }

            return valid;
          },
        },
        async onExistingUserSignUp({ user }, request) {
          if (name.startsWith("signup-synthetic-fields")) {
            return;
          }
          events.push({
            stage: "existing-user",
            user,
            request: request
              ? {
                  method: request.method,
                  path: new URL(request.url).pathname.slice(basePath.length),
                  marker: request.headers.get("x-test-policy-marker"),
                  contentType: request.headers.get("content-type"),
                }
              : null,
          });

          if (mode === "existing-block") {
            await new Promise<void>((resolve) => {
              releaseExisting = resolve;
            });
          }

          if (mode === "existing-error") {
            throw new Error("Actual existing-user callback failed");
          }

          if (mode === "existing-api") {
            throw new APIError("FORBIDDEN", {
              code: "EXISTING_REJECTED",
              message: "Configured existing-user rejected",
            });
          }

          events.push({ stage: "existing-complete" });
        },
        ...([
          "signup-custom",
          "signup-synthetic-id-custom",
          "signup-synthetic-fields-custom",
        ].includes(name)
          ? {
              customSyntheticUser({ coreFields, additionalFields, id }) {
                events.push({ stage: "synthetic-user", coreFields, additionalFields, id });

                if (mode === "synthetic-error") {
                  throw new Error("Actual synthetic-user callback failed");
                }

                if (mode === "synthetic-api") {
                  throw new APIError("FORBIDDEN", {
                    code: "SYNTHETIC_REJECTED",
                    message: "Configured synthetic-user rejected",
                  });
                }

                if (name === "signup-synthetic-id-custom") return { ...coreFields, id };
                if (name === "signup-synthetic-fields-custom") {
                  return {
                    ...coreFields,
                    id,
                    ...(typeof additionalFields.syntheticTier === "string"
                      ? { syntheticTier: `custom:${additionalFields.syntheticTier}` }
                      : {}),
                    syntheticSecret: "custom-private",
                    unknownApplication: "must-not-escape",
                  };
                }
                return {
                  ...coreFields,
                  id,
                  name: `Synthetic ${coreFields.name}`,
                  emailVerified: true,
                  image: "https://images.example/synthetic.png",
                  role: "admin",
                  privateCredential: "unreturned-application-data",
                };
              },
            }
          : {}),
        async sendResetPassword({ user, url, token }, request) {
          events.push({
            stage: "reset-delivery",
            user,
            url,
            token,
            request: request
              ? {
                  method: request.method,
                  path: new URL(request.url).pathname.slice(basePath.length),
                  marker: request.headers.get("x-test-policy-marker"),
                  contentType: request.headers.get("content-type"),
                }
              : null,
          });
          if (mode === "reset-sender-error") {
            throw new Error("Actual configured reset sender failed");
          }
        },
        async onPasswordReset({ user }, request) {
          events.push({
            stage: "password-reset",
            user,
            request: request
              ? {
                  method: request.method,
                  path: new URL(request.url).pathname.slice(basePath.length),
                  marker: request.headers.get("x-test-policy-marker"),
                  contentType: request.headers.get("content-type"),
                }
              : null,
          });
          if (mode === "reset-callback-error") {
            throw new Error("Actual configured reset callback failed");
          }
          if (mode === "reset-callback-api") {
            throw new APIError("FORBIDDEN", {
              code: "RESET_REJECTED",
              message: "Configured reset callback rejected",
            });
          }
        },
      },
    });
    profiles.set(name, instance);
  }

  return {
    profiles,
    async handle(request: Request): Promise<Response | undefined> {
      const url = new URL(request.url);
      if (url.pathname === "/__test/signup-policy/synthetic-fields") {
        return Response.json({
          users: database
            .query(
              'SELECT id, synthetic_tier AS syntheticTier, synthetic_secret AS syntheticSecret, synthetic_locale AS syntheticLocale, synthetic_note AS syntheticNote FROM "user" ORDER BY "createdAt", id',
            )
            .all(),
        });
      }

      if (url.pathname === "/__test/signup-policy/state") {
        const profile = profiles.get(url.searchParams.get("profile") ?? "signup-standard");

        if (!profile) {
          return Response.json({ message: "unknown fixture profile" }, { status: 400 });
        }

        const context = await profile.$context;
        const read = (model: "user" | "account" | "session" | "verification") =>
          context.adapter.findMany<Record<string, unknown>>({
            model,
            sortBy: { field: "createdAt", direction: "asc" },
          });
        return Response.json({
          users: await read("user"),
          accounts: await read("account"),
          sessions: await read("session"),
          verifications: await read("verification"),
          events,
        });
      }

      if (url.pathname !== "/__test/signup-policy" || request.method !== "POST") {
        return;
      }

      const body = (await request.json()) as {
        operation?: string;
        mode?: string;
        profile?: string;
        accountId?: string;
        stage?: string;
        password?: string;
      };

      if (body.operation === "mode") {
        mode = body.mode ?? "normal";
        events.length = 0;
        return Response.json({ status: true, mode });
      }

      if (body.operation === "release-existing") {
        releaseExisting?.();
        releaseExisting = undefined;
        return Response.json({ status: true });
      }

      if (body.operation === "wait-stage") {
        const deadline = Date.now() + 4000;
        while (!events.some((event) => event.stage === body.stage)) {
          if (Date.now() >= deadline) {
            return Response.json(
              { message: "application callback did not reach requested stage" },
              { status: 408 },
            );
          }
          await Bun.sleep(5);
        }
        return Response.json({ events });
      }

      if (body.operation === "clear-password") {
        const context = await profiles.get(body.profile ?? "signup-standard")!.$context;
        await context.internalAdapter.updateAccount(body.accountId!, {
          password: body.password ?? null,
        });
        return Response.json({ status: true });
      }

      return Response.json({ message: "unknown fixture operation" }, { status: 400 });
    },
  };
}
