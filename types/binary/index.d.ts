// define only what we use

interface BinaryStream<T>
  extends Record<
    | "word8"
    | "word8u"
    | "word8s"
    | `word${"8" | "16" | "32" | "64"}${
        | "le"
        | "lu"
        | "ls"
        | "be"
        | "bu"
        | "bs"}`,
    (prop: string) => BinaryStream<T>
  > {
  buffer(prop: string, lengthProp: string): BinaryStream<T>;
  buffer(prop: string, length: number): BinaryStream<T>;
  tap(callback: (args: T) => void): BinaryStream<T>;
}

export function stream<T>(source: Buffer): BinaryStream<T>;
