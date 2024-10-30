import { generateRecords, writeRecordsToFile } from './cidr-utils';

const records = generateRecords(14000);
writeRecordsToFile(records, 'testData.ts');
