import type Fastify from "fastify";

declare module "fastify" {
	interface FastifyRequest {
		time: epoch;
		time_milli: epoch_milli;
		session: {
			valid: boolean;
			info?: AuthSession;
		};
	}
}