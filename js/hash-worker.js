self.onmessage = async (e) => {
  const { buf, X, Y, Z } = e.data;
  const part = new Uint8Array((X - 0) + (Z - Y));
  part.set(buf.slice(0, X), 0);
  part.set(buf.slice(Y, Z), X);
  const d = await crypto.subtle.digest('SHA-256', part);
  self.postMessage(new Uint8Array(d), [d]);
};
