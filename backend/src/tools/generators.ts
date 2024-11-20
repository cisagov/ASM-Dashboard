import { generateRecords, writeRecordsToFile } from './cidr-utils';

const records = generateRecords(9000);
writeRecordsToFile(records, 'dmzLzSyncTestData.ts');
