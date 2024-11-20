import { Address4 } from 'ip-address';
import * as fs from 'fs';

export interface CidrInfo {
  network: string;
  startIp: string;
  endIp: string;
}

export const getCidrInfo = (cidr: string): CidrInfo | null => {
  if (cidr === '') return null;
  try {
    const [ip, subnet] = cidr.split('/');
    if (ip && subnet) {
      const prefixLength = parseInt(subnet, 10);

      // Validate the IP address
      if (!Address4.isValid(ip) || prefixLength > 32) {
        throw new Error('Invalid CIDR notation');
      }

      // Special handling for /32 CIDR blocks
      if (prefixLength === 32) {
        return {
          network: ip,
          startIp: ip,
          endIp: ip
        };
      }

      const address = new Address4(ip);

      // Calculate the number of hosts in the subnet using BigInt
      const hostBits = 32 - prefixLength;
      const numHosts = BigInt(Math.pow(2, hostBits));

      // Convert IP to BigInt
      const baseInt = BigInt(address.bigInteger().toString());

      // Calculate the start IP (network address) as a BigInt
      const startIpInt = baseInt & (BigInt(-1) << BigInt(hostBits));
      const startIp = Address4.fromBigInteger(startIpInt.toString()).address;

      // Calculate the end IP by adding numHosts - 1 to startIpInt
      const endIpInt = startIpInt + (numHosts - BigInt(1));
      const endIp = Address4.fromBigInteger(endIpInt.toString()).address;

      const cidrInfo = {
        network: `${ip}/${subnet}`,
        startIp,
        endIp
      };
      return cidrInfo;
    }
    const cidrInfo = {
      network: ip,
      startIp: ip,
      endIp: ip
    };
    return cidrInfo;
  } catch (error) {
    return null;
  }
};

import { v4 as uuidv4 } from 'uuid';

interface Location {
  country: string;
  country_name: string;
  county: string;
  county_fips: string;
  gnis_id: number;
  name: string;
  state: string;
  state_fips: string;
  state_name: string;
}

interface Agency {
  acronym: string;
  location: Location;
  name: string;
  type: string | null;
}

interface Record {
  _id: string;
  agency: string; // JSON stringified
  children: string[] | null;
  networks: string; // JSON stringified
  report_types: string; // JSON stringified
  scan_types: string; // JSON stringified
  stakeholder: boolean;
  retired: boolean;
  period_start: string;
  enrolled: string;
}

// Sets to store unique values globally
const uniqueNetworks = new Set<string>();
const uniqueAcronyms = new Set<string>();
const recordsMap = new Map<string, Record>();

const generateRandomCIDR = (): string => {
  const randomOctet = () => Math.floor(Math.random() * 256);
  const subnet = Math.floor(Math.random() * 32);
  return `${randomOctet()}.${randomOctet()}.${randomOctet()}.${randomOctet()}/${subnet}`;
  // return `${randomOctet()}.${randomOctet()}.${randomOctet()}.${randomOctet()}`;
};

// Generate a unique CIDR
const generateUniqueCIDR = (): string => {
  let cidr;
  do {
    cidr = generateRandomCIDR();
  } while (uniqueNetworks.has(cidr)); // Ensure uniqueness across all records
  uniqueNetworks.add(cidr);
  return cidr;
};

// Generate a unique acronym
const generateUniqueAcronym = (): string => {
  let acronym;
  do {
    acronym = uuidv4().slice(0, 4).toUpperCase();
  } while (uniqueAcronyms.has(acronym));
  uniqueAcronyms.add(acronym);
  return acronym;
};

const generateLocation = (acronym: string): Location => ({
  country: 'US',
  country_name: 'United States',
  county: 'Sample County',
  county_fips: '001',
  gnis_id: Math.floor(Math.random() * 1000000),
  name: `City of ${acronym}`,
  state: 'CA',
  state_fips: '06',
  state_name: 'California'
});

const generateAgency = (acronym: string): Agency => ({
  acronym,
  location: generateLocation(acronym),
  name: `City of ${acronym}, CA`,
  type: Math.random() < 0.5 ? 'LOCAL' : null // Randomly decide if this is a sector
});

const generateDateString = (startYear: number, endYear: number): string => {
  const start = new Date(startYear, 0, 1).getTime();
  const end = new Date(endYear, 11, 31).getTime();
  const date = new Date(start + Math.random() * (end - start));
  return date.toISOString();
};

// Function to generate globally unique networks array
const generateUniqueNetworksArray = (): string[] => {
  const networks: string[] = [];
  const numNetworks = Math.floor(Math.random() * 10) + 3;

  while (networks.length < numNetworks) {
    networks.push(generateUniqueCIDR());
  }

  return networks;
};

const generateChildren = (currentAcronym: string): string[] | null => {
  const childAcronyms = Array.from(uniqueAcronyms).filter(
    (acronym) => acronym !== currentAcronym
  );
  const numChildren =
    Math.random() < 0.5 ? 0 : Math.floor(Math.random() * 3) + 1; // Sometimes null, other times 1-3 children
  if (numChildren === 0) return null;
  return childAcronyms.slice(0, numChildren);
};

const generateRecord = (): Record => {
  const acronym = generateUniqueAcronym();
  const agency = generateAgency(acronym);

  const record: Record = {
    _id: acronym,
    agency: JSON.stringify(agency),
    children: generateChildren(acronym),
    networks: JSON.stringify(generateUniqueNetworksArray()),
    report_types: JSON.stringify(['CYHY']),
    scan_types: JSON.stringify(['CYHY']),
    stakeholder: Math.random() < 0.7,
    retired: Math.random() < 0.1 ? true : false,
    period_start: generateDateString(2024, 2024),
    enrolled: generateDateString(2013, 2023)
  };

  recordsMap.set(acronym, record); // Add record to map for reference by children
  return record;
};

export const generateRecords = (N: number): Record[] =>
  Array.from({ length: N }, generateRecord);

export const writeRecordsToFile = (records: Record[], filePath: string) => {
  const content = `export const TEST_DATA = ${JSON.stringify(
    records,
    null,
    2
  )};`;

  fs.writeFileSync(filePath, content);
  console.log(`Data successfully written to ${filePath}`);
};
