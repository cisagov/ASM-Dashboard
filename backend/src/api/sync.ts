import { parse } from 'papaparse';
import S3Client from '../tasks/s3-client';
import { createChecksum } from '../tools/csv-utils';
import { REGION_STATE_MAP, wrapHandler } from './helpers';
import { Client } from 'pg';
import { v4 } from 'uuid';
import { getCidrInfo } from '../tools/cidr-utils';
import { Cidr } from 'src/models/mini_data_lake/cidrs';
import { DL_Organization } from 'src/models';

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
  children: string;
  state_name: string;
  state_fips: string;
  county: string;
  county_fips: string;
  agency_type: string;
}

interface RawOrganization {
  cidrs: string;
  name: string;
  report_types: string;
  scan_types: string;
  stakeholder: boolean;
  retired: boolean;
  period_start: string;
  enrolled: string;
  acronym: string;
  country: string;
  country_name: string;
  state: string;
  children: string;
  state_name: string;
  state_fips: string;
  county: string;
  county_fips: string;
  agency_type: string;
}

type ParsedOrganization = DL_Organization;

async function upsertOrganization(client: Client, org: DL_Organization) {
  const {
    id,
    name,
    acronym,
    enrolledInVsTimestamp,
    periodStartVsTimestamp,
    createdDate,
    updatedDate,
    retired,
    peReportOn,
    pePremium,
    peDemo,
    peRunScans,
    type,
    stakeholder,
    initStage,
    scheduler,
    reportTypes,
    scanTypes,
    scanLimits,
    scanWindows
  } = org;

  const params = [
    id,
    name,
    acronym,
    enrolledInVsTimestamp || 'now()',
    periodStartVsTimestamp || 'now()',
    createdDate,
    updatedDate,
    !!retired,
    !!peReportOn,
    !!pePremium,
    !!peDemo,
    !!peRunScans,
    type,
    !!stakeholder,
    initStage,
    scheduler,
    JSON.stringify(reportTypes),
    JSON.stringify(scanTypes),
    JSON.stringify(scanWindows),
    JSON.stringify(scanLimits),
    JSON.stringify(org?.cidrs?.map((item) => item.network) ?? []),
    false
  ];

  const result = await client.query(
    `INSERT INTO public.organization (
      id, name, acronym, enrolled_in_vs_timestamp, period_start_vs_timestamp,
      created_at, updated_at, retired, pe_report_on, pe_premium, pe_demo,
      pe_run_scans, type, stakeholder, init_stage, scheduler,
      report_types, scan_types, scan_windows, scan_limits, ip_blocks, is_passive
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
    ON CONFLICT (acronym) DO UPDATE SET
      name = EXCLUDED.name, acronym = EXCLUDED.acronym,
      enrolled_in_vs_timestamp = EXCLUDED.enrolled_in_vs_timestamp,
      period_start_vs_timestamp = EXCLUDED.period_start_vs_timestamp,
      created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at,
      retired = EXCLUDED.retired, pe_report_on = EXCLUDED.pe_report_on,
      pe_premium = EXCLUDED.pe_premium, pe_demo = EXCLUDED.pe_demo,
      pe_run_scans = EXCLUDED.pe_run_scans, type = EXCLUDED.type,
      stakeholder = EXCLUDED.stakeholder,
      init_stage = EXCLUDED.init_stage, scheduler = EXCLUDED.scheduler,
      report_types = EXCLUDED.report_types, scan_types = EXCLUDED.scan_types,
      scan_windows = EXCLUDED.scan_windows, scan_limits = EXCLUDED.scan_limits
    RETURNING id;`,
    params
  );

  return result.rows[0].id;
}

// Upsert a location and return its ID
async function upsertLocation(client: Client, location) {
  const {
    id,
    name,
    countryAbrv,
    country,
    county,
    countyFips,
    gnisId,
    stateAbrv,
    stateFips,
    state
  } = location;

  const result = await client.query(
    `INSERT INTO public.location (
      id, name, country_abrv, country, county, county_fips, gnis_id,
      state_abrv, state_fips, state
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    ON CONFLICT (id) DO UPDATE SET
      name = EXCLUDED.name, country_abrv = EXCLUDED.country_abrv,
      country = EXCLUDED.country, county = EXCLUDED.county,
      county_fips = EXCLUDED.county_fips, gnis_id = EXCLUDED.gnis_id,
      state_abrv = EXCLUDED.state_abrv, state_fips = EXCLUDED.state_fips,
      state = EXCLUDED.state
    RETURNING id;`,
    [
      id,
      name,
      countryAbrv,
      country,
      county,
      countyFips,
      gnisId,
      stateAbrv,
      stateFips,
      state
    ]
  );

  return result.rows[0].id;
}

// Link organization to location
async function linkOrganizationLocation(client: Client, orgId, locationId) {
  await client.query(
    `UPDATE public.organization SET location_id = $1 WHERE id = $2;`,
    [locationId, orgId]
  );
}

// Upsert sectors and link them to an organization
async function upsertSectors(client: Client, orgId, sectors) {
  for (const sector of sectors) {
    const { id, name, acronym, retired } = sector;

    const sectorResult = await client.query(
      `INSERT INTO public.sector (
        id, name, acronym, retired
      ) VALUES ($1, $2, $3, $4)
      ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name, retired = EXCLUDED.retired
      RETURNING id;`,
      [id, name, acronym, retired]
    );

    const sectorId = sectorResult.rows[0].id;
    await client.query(
      `INSERT INTO public.sector_organizations (organization_id, sector_id)
       VALUES ($1, $2)
       ON CONFLICT DO NOTHING;`,
      [orgId, sectorId]
    );
  }
}

// Upsert CIDRs and link them to an organization
async function upsertCIDRs(client: Client, orgId, cidrs) {
  for (const cidr of cidrs) {
    const { id, network, startIp, endIp, retired, createdDate, updatedAt } =
      cidr;

    const cidrResult = await client.query(
      `INSERT INTO public.cidr (
        id, network, start_ip, end_ip, retired, created_date, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT (id) DO UPDATE SET
        network = EXCLUDED.network, start_ip = EXCLUDED.start_ip,
        end_ip = EXCLUDED.end_ip, retired = EXCLUDED.retired,
        updated_at = EXCLUDED.updated_at
      RETURNING id;`,
      [id, network, startIp, endIp, retired, createdDate, updatedAt]
    );

    const cidrId = cidrResult.rows[0].id;
    await client.query(
      `INSERT INTO public.cidr_organizations (organization_id, cidr_id)
       VALUES ($1, $2)
       ON CONFLICT DO NOTHING;`,
      [orgId, cidrId]
    );
  }
}

// Recursive function to handle an organization and its related entities
async function handleOrganization(client: Client, org, parentOrgId = null) {
  const orgId = await upsertOrganization(client, org);

  // Link parent organization if provided
  if (parentOrgId) {
    await client.query(
      `UPDATE public.organization SET parent_id = $1 WHERE id = $2;`,
      [parentOrgId, orgId]
    );
  }

  // Link location if specified
  if (org.location) {
    const locationId = await upsertLocation(client, org.location);
    try {
      await linkOrganizationLocation(client, orgId, locationId);
    } catch (error) {
      console.log(
        `Error occurred while linking location and organization ${error}`
      );
    }
  }

  // Link sectors if specified
  if (org.sectors) {
    try {
      await upsertSectors(client, orgId, org.sectors);
    } catch (error) {
      console.log(
        `Error occurred while creating and linking sectors and organization ${error}`
      );
    }
  }

  // Link CIDRs if specified
  if (org.cidrs) {
    try {
      await upsertCIDRs(client, orgId, org.cidrs);
    } catch (error) {
      console.log(
        `Error occurred while creating and linking cidrs and organization ${error}`
      );
    }
  }

  // Process child organizations if any
  if (org.children && org.children.length > 0) {
    try {
      for (const child of org.children) {
        await handleOrganization(client, child, orgId);
      }
    } catch (error) {
      console.log(
        `Error occurred while creating and linking children and organization ${error}`
      );
    }
  }
}

// Process an array of organizations
async function processOrganizations(client: Client, organizations) {
  for (const org of organizations) {
    await handleOrganization(client, org);
  }
}

export const ingest = wrapHandler(async (event) => {
  const originalChecksum = event.headers['x-checksum'];
  const newChecksum = event.body ? createChecksum(event.body) : '';
  const csvData = event.body;

  if (originalChecksum === newChecksum) {
    // Checksums match, upload the file to S3
    let uploadKey: string = '';
    const s3Client = new S3Client();
    if (csvData) {
      try {
        const { key } = await s3Client.saveCSV(
          csvData,
          '',
          process.env.IS_LOCAL ? 'crossfeed-local-exports' : 'crossfeed-lz-sync'
        );
        uploadKey = key;
        console.log('Uploaded CSV data to S3');
      } catch (error) {
        console.error(`Error occurred pushing data to S3: ${error}`);
      }

      const data = await s3Client.getObject(
        uploadKey,
        process.env.IS_LOCAL ? 'crossfeed-local-exports' : 'crossfeed-lz-sync'
      );
      const fileContents = (await data?.promise())?.Body?.toString('utf-8');
      if (fileContents) {
        const parsed = parse<ParsedOrganization>(fileContents, {
          header: true,
          transform(value, field) {
            if (
              field === 'children' ||
              field === 'sectors' ||
              field === 'location' ||
              field === 'cidrs'
            ) {
              return JSON.parse(value);
            }
            return value;
          }
        });
        const client = new Client({
          user: process.env.MDL_USERNAME,
          host: process.env.MDL_HOST,
          database: process.env.MDL_DATABASE,
          password: process.env.MDL_PASSWORD
        });
        await client.connect();
        console.time(`Timer: ${parsed.data[0].acronym}`);
        await processOrganizations(client, parsed.data);

        console.timeEnd(`Timer: ${parsed.data[0].acronym}`);
      } else {
        console.log('File contents empty');
      }
    }
  }

  return {
    statusCode: 200,
    body: ''
  };
});
