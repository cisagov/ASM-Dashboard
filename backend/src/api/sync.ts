import { parse } from 'papaparse';
import S3Client from '../tasks/s3-client';
import { createChecksum } from '../tools/csv-utils';
import { REGION_STATE_MAP, wrapHandler } from './helpers';
import { Client } from 'pg';
import { v4 } from 'uuid';
import { getCidrInfo } from '../tools/cidr-utils';

interface ShapedOrg {
  networks: string[];
  name: string;
  report_types: string;
  scan_types: string;
  stakeholder: string;
  retired: string;
  period_start: string;
  enrolled: string;
  acronym: string;
  country: string;
  country_name: string;
  state: string;
  state_name: string;
  state_fips: string;
  county: string;
  county_fips: string;
  agency_type: string;
}

const persistOrgAndCidrs = async (client: any, org: ShapedOrg) => {
  const report_types = org.report_types.includes(',')
    ? org.report_types.split(',')
    : [org.report_types];
  const scan_types = org.scan_types.includes(',')
    ? org.scan_types.split(',')
    : [org.scan_types];

  try {
    const insertOrgText = `
      INSERT INTO public.organization (
        id, name, report_types, scan_types, stakeholder, retired, acronym, country,
        country_name, state, state_name, state_fips, county, county_fips, agency_type,
        created_at, updated_at, ip_blocks, is_passive, enrolled_in_vs_timestamp,
        period_start_vs_timestamp, region_id
      )
      VALUES (
        uuid_generate_v4(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
        $14, $15, $16, $17, $18, $19, $20, $21
      )
      RETURNING id;
    `;
    const result = await client.query(insertOrgText, [
      org.name,
      JSON.stringify(report_types),
      JSON.stringify(scan_types),
      org.stakeholder,
      org.retired === '' ? false : org.retired,
      org.acronym,
      org.country,
      org.country_name,
      org.state,
      org.state_name,
      org.state_fips,
      org.county,
      org.county_fips,
      org.agency_type,
      'now()',
      'now()',
      'N/A',
      'false',
      org.enrolled === '' ? 'now' : org.enrolled,
      org.period_start === '' ? 'now()' : org.period_start,
      REGION_STATE_MAP[org.state_name]
    ]);
    const organizationId = result?.rows[0].id;

    // Collect CIDR info and batch insert
    const cidrValues = org.networks
      .map((network) => {
        const cidrInfo = getCidrInfo(network);
        return cidrInfo
          ? `('${v4()}', '${cidrInfo.network}', '${cidrInfo.startIp}', '${
              cidrInfo.endIp
            }', 'now()', 'now()')`
          : null;
      })
      .filter(Boolean);

    const insertCidrText = `
      INSERT INTO public.cidr (id, network, start_ip, end_ip, created_date, updated_at)
      VALUES ${cidrValues.join(', ')}
      RETURNING id;
    `;

    const cidrResults = await client.query(insertCidrText);
    const cidrIds = cidrResults.rows.map((row) => row.id);

    // Batch insert CIDR-to-Organization links
    const cidrOrgLinkValues = cidrIds
      .map((id) => `('${id}', '${organizationId}')`)
      .join(', ');

    const insertCidrOrgLinkText = `
      INSERT INTO public.cidr_organizations (cidr_id, organization_id)
      VALUES ${cidrOrgLinkValues};
    `;

    await client.query(insertCidrOrgLinkText);
  } catch (error) {
    console.log(`Error while saving organization - ${org.name} ${error}`);
  }
};

export const ingest = wrapHandler(async (event) => {
  console.time('IngestTimer');
  const originalChecksum = event.headers['x-checksum'];
  const newChecksum = event.body ? createChecksum(event.body) : '';
  const csvData = event.body;

  if (originalChecksum === newChecksum) {
    // Checksums match, upload the file to S3
    let uploadKey: string = '';
    const s3Client = new S3Client(false);
    if (csvData) {
      try {
        const { key } = await s3Client.saveCSV(
          csvData,
          '',
          'crossfeed-lz-sync'
        );
        uploadKey = key;
        console.log('Uploaded CSV data to S3');
      } catch (error) {
        console.error(`Error occurred pushing data to S3: ${error}`);
      }
      try {
        const data = await s3Client.getObject(uploadKey, 'crossfeed-lz-sync');
        const fileContents = (await data?.promise())?.Body?.toString('utf-8');
        if (fileContents) {
          const parsed = parse<ShapedOrg>(fileContents, {
            header: true,
            transform: (v, f) => {
              if (f === 'networks') {
                return v.split(',');
              }
              return v;
            }
          });
          const client = new Client({
            user: process.env.MDL_USERNAME,
            host: process.env.MDL_HOST,
            database: process.env.MDL_DATABASE,
            password: process.env.MDL_PASSWORD
          });
          await client.connect();

          const persists = parsed.data.map((org) => {
            return persistOrgAndCidrs(client, org);
          });

          await Promise.all(persists);
          console.timeEnd('IngestTimer');
        } else {
          console.log('File contents empty');
        }
      } catch (error) {
        console.error(`Error occurred fetching object from S3: ${error} `);
      }
    }
  }

  return {
    statusCode: 200,
    body: ''
  };
});
