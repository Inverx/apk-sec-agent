// 增量 SHA-256（WebCrypto 的 subtle.digest 只支持一次性输入，
// 分片上传边读边算需要一个流式实现；纯 TS，无依赖）

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

export class Sha256 {
  private state = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  private buffer = new Uint8Array(64);
  private bufferLength = 0;
  private bytesHashed = 0;
  private readonly w = new Uint32Array(64);

  update(data: Uint8Array): this {
    let position = 0;
    this.bytesHashed += data.length;
    if (this.bufferLength > 0) {
      const take = Math.min(64 - this.bufferLength, data.length);
      this.buffer.set(data.subarray(0, take), this.bufferLength);
      this.bufferLength += take;
      position = take;
      if (this.bufferLength === 64) {
        this.processBlock(this.buffer, 0);
        this.bufferLength = 0;
      }
    }
    while (position + 64 <= data.length) {
      this.processBlock(data, position);
      position += 64;
    }
    if (position < data.length) {
      this.buffer.set(data.subarray(position), 0);
      this.bufferLength = data.length - position;
    }
    return this;
  }

  digestHex(): string {
    const bitLengthHi = Math.floor((this.bytesHashed * 8) / 0x100000000);
    const bitLengthLo = (this.bytesHashed * 8) >>> 0;
    const padding = new Uint8Array(((this.bufferLength < 56 ? 56 : 120) - this.bufferLength) + 8);
    padding[0] = 0x80;
    const view = new DataView(padding.buffer);
    view.setUint32(padding.length - 8, bitLengthHi);
    view.setUint32(padding.length - 4, bitLengthLo);
    const tail = new Uint8Array(this.buffer.subarray(0, this.bufferLength));
    const final = new Uint8Array(tail.length + padding.length);
    final.set(tail);
    final.set(padding, tail.length);

    // process remaining blocks without mutating state twice
    let position = 0;
    if (this.bufferLength > 0 && tail.length >= 64) {
      // unreachable by construction; kept for safety
    }
    while (position + 64 <= final.length) {
      this.processBlock(final, position);
      position += 64;
    }

    return Array.from(this.state)
      .map((word) => word.toString(16).padStart(8, "0"))
      .join("");
  }

  private processBlock(block: Uint8Array, offset: number): void {
    const w = this.w;
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = (block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3];
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    const s = this.state;
    let [a, b, c, d, e, f, g, h] = s;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }
    s[0] = (s[0] + a) >>> 0;
    s[1] = (s[1] + b) >>> 0;
    s[2] = (s[2] + c) >>> 0;
    s[3] = (s[3] + d) >>> 0;
    s[4] = (s[4] + e) >>> 0;
    s[5] = (s[5] + f) >>> 0;
    s[6] = (s[6] + g) >>> 0;
    s[7] = (s[7] + h) >>> 0;
  }
}

/** 计算整个 Blob 的 SHA-256，边读边算，onProgress 上报 0-1 */
export async function hashBlob(
  blob: Blob,
  onProgress?: (ratio: number) => void,
): Promise<string> {
  const hasher = new Sha256();
  const chunkSize = 4 * 1024 * 1024;
  for (let offset = 0; offset < blob.size; offset += chunkSize) {
    const chunk = new Uint8Array(await blob.slice(offset, offset + chunkSize).arrayBuffer());
    hasher.update(chunk);
    onProgress?.(Math.min(offset + chunkSize, blob.size) / blob.size);
  }
  return hasher.digestHex();
}
