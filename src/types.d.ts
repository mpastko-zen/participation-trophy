declare module 'snarkjs' {
  export const groth16: {
    fullProve(
      input: Record<string, unknown>,
      wasmFile: string,
      zkeyFile: string,
    ): Promise<{ proof: Record<string, unknown>; publicSignals: string[] }>;
    verify(vk: unknown, publicSignals: string[], proof: unknown): Promise<boolean>;
  };
  export const zKey: {
    exportVerificationKey(zkeyFile: string): Promise<unknown>;
  };
}
declare module 'circomlibjs' {
  export function buildPoseidon(): Promise<
    ((inputs: (bigint | number | string)[]) => Uint8Array) & {
      F: { toString(v: Uint8Array): string; toObject(v: Uint8Array): bigint };
    }
  >;
}
