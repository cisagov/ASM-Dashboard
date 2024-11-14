export const chunkBySize = <T>(
  array: T[],
  maxSize: number
): { chunks: T[][]; chunkBounds: { start: number; end: number }[] } => {
  const chunks: T[][] = [];
  const chunkBounds: { start: number; end: number }[] = [];
  let currentChunk: T[] = [];
  let currentSize = 0;
  let startIndex = 0;

  const calculateSize = (item: T): number => {
    return Buffer.byteLength(JSON.stringify(item), 'utf8');
  };

  for (let i = 0; i < array.length; i++) {
    const item = array[i];
    const itemSize = calculateSize(item);

    if (currentSize + itemSize > maxSize) {
      if (currentChunk.length === 0 && itemSize > maxSize) {
        throw new Error(
          `Item size (${itemSize} bytes) exceeds the maximum chunk size (${maxSize} bytes).`
        );
      }
      chunks.push(currentChunk);
      chunkBounds.push({ start: startIndex, end: i - 1 });
      currentChunk = [];
      currentSize = 0;
      startIndex = i;
    }

    currentChunk.push(item);
    currentSize += itemSize;
  }

  if (currentChunk.length > 0) {
    chunks.push(currentChunk);
    chunkBounds.push({ start: startIndex, end: array.length - 1 });
  }

  return { chunks, chunkBounds };
};
