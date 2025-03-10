import React from 'react';
import { Box, Grid, Link, Typography } from '@mui/material';
import { useAuthContext } from 'context';
import logo from '../../assets/cyhydashboard.svg';
import * as FooterStyles from './styleFooter';
import { Stack } from '@mui/system';
import packageJson from '../../../package.json';

export const CrossfeedFooter: React.FC = (props) => {
  const { logout, user } = useAuthContext();
  const FooterRoot = FooterStyles.FooterRoot;
  const footerClasses = FooterStyles.footerClasses;
  const versionNumber = packageJson.version;

  return (
    <FooterRoot>
      <Box className={footerClasses.footerBox}>
        <Grid className={footerClasses.footerContainer} container>
          <Grid className={footerClasses.footerLogo} item xs={12} sm={3}>
            <Stack direction="row" spacing={1}>
              <Link
                href="/"
                aria-label={`CyHy Dashboard version ${versionNumber}`}
              >
                <img src={logo} alt="CyHy Dashboard Icon Navigate Home" />
              </Link>
              {user && (
                <Typography variant="caption" color="white" tabIndex={0}>
                  v. {versionNumber}
                </Typography>
              )}
            </Stack>
          </Grid>
          {user && (
            <Grid className={footerClasses.footerNavItem} item xs={12} sm={2}>
              <Link className={footerClasses.footerNavLink} href="/">
                Home
              </Link>
            </Grid>
          )}
          {/* <Grid className={footerClasses.footerNavItem} item xs={12} sm={2}>
            <p>
              <Link
                className={footerClasses.footerNavLink}
                href="https://docs.crossfeed.cyber.dhs.gov/"
                target="_blank"
              >
                Documentation
              </Link>
            </p>
          </Grid> */}
          <Grid className={footerClasses.footerNavItem} item xs={12} sm={2}>
            <p>
              <Link
                className={footerClasses.footerNavLink}
                href="https://www.cisa.gov"
                target="_blank"
                rel="noopener noreferrer"
              >
                CISA Homepage
              </Link>
            </p>
          </Grid>
          <Grid className={footerClasses.footerNavItem} item xs={12} sm={2}>
            <p>
              <Link
                className={footerClasses.footerNavLink}
                href="mailto:vulnerability@cisa.dhs.gov"
              >
                Contact Us
              </Link>
            </p>
          </Grid>
          {user && (
            <Grid className={footerClasses.footerNavItem} item xs={12} sm={2}>
              <p>
                <Link
                  className={footerClasses.footerNavLink}
                  href="/"
                  onClick={logout}
                >
                  Logout
                </Link>
              </p>
            </Grid>
          )}
        </Grid>
      </Box>
    </FooterRoot>
  );
};
