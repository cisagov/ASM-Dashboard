import React, { useCallback, useState } from 'react';
import { ImportExport } from 'components';
import { Organization } from 'types';
import { useAuthContext } from 'context';
import { OrganizationList } from 'components/OrganizationList';
import { Typography } from '@mui/material';
import { Box, Stack } from '@mui/system';

export const Organizations: React.FC = () => {
  const { user, apiGet, apiPost } = useAuthContext();
  const [organizations, setOrganizations] = useState<Organization[]>([]);

  const fetchOrganizations = useCallback(async () => {
    try {
      const rows = await apiGet<Organization[]>('/v2/organizations/');
      setOrganizations(rows);
    } catch (e) {
      console.error(e);
    }
  }, [apiGet]);

  React.useEffect(() => {
    fetchOrganizations();
  }, [apiGet, fetchOrganizations]);

  return (
    <Box mb={3} mt={3} display="flex" justifyContent="center">
      <Stack spacing={2} sx={{ width: '70%' }}>
        <Typography
          fontSize={34}
          fontWeight="medium"
          letterSpacing={0}
          my={3}
          variant="h1"
        >
          Organizations
        </Typography>
        <OrganizationList></OrganizationList>
        {user?.userType === 'globalAdmin' && (
          <>
            <ImportExport<Organization>
              name="organizations"
              fieldsToImport={[
                'name',
                'acronym',
                'rootDomains',
                'ipBlocks',
                'isPassive',
                'tags',
                'country',
                'state',
                'stateFips',
                'stateName',
                'county',
                'countyFips'
              ]}
              onImport={async (results) => {
                // TODO: use a batch call here instead.
                const createdOrganizations = [];
                for (const result of results) {
                  try {
                    createdOrganizations.push(
                      await apiPost('/organizations_upsert/', {
                        body: {
                          ...result,
                          // These fields are initially parsed as strings, so they need
                          // to be converted to arrays.
                          ipBlocks: (
                            (result.ipBlocks as unknown as string) || ''
                          ).split(','),
                          rootDomains: (
                            (result.rootDomains as unknown as string) || ''
                          ).split(','),
                          tags: ((result.tags as unknown as string) || '')
                            .split(',')
                            .map((tag) => ({
                              name: tag
                            }))
                        }
                      })
                    );
                  } catch (e: any) {
                    console.error('Error uploading Entry: ' + e);
                  }
                }
                setOrganizations(organizations.concat(...createdOrganizations));
                window.location.reload();
              }}
            />
          </>
        )}
      </Stack>
    </Box>
  );
};

export default Organizations;
