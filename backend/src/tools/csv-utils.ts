import { createHash } from 'crypto';

type JsonObject = {
  [key: string]: any;
};

export const createChecksum = (input: string) => {
  const hash = createHash('sha256');
  hash.update(input);
  return hash.digest('hex');
};

export const jsonToCSV = (jsonArray: JsonObject[]): string => {
  if (jsonArray.length === 0) return '';

  // Extract headers (keys) from the first object in the array
  const headers: string[] = Object.keys(jsonArray[0]);

  // Map each object to a CSV row
  const rows: string[] = jsonArray.map((obj: JsonObject) =>
    headers
      .map((header) =>
        Array.isArray(obj[header])
          ? `"${obj[header].join(',')}"`
          : `"${
              obj[header] !== null && obj[header] !== undefined
                ? obj[header]
                : ''
            }"`
      )
      .join(',')
  );

  // Combine headers and rows into CSV format
  const csv: string = [headers.join(','), ...rows].join('\n');

  return csv;
};
