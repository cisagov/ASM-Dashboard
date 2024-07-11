import React from 'react';
import { Grid, Paper, Typography } from '@mui/material';
import * as RiskStyles from './style';

const testData = {
  scanDate: '5 Jul 2024',
  activeVulns: '100',
  newVulns: '20',
  reopenedVulns: '30',
  sensitiveContent: '4'
};

const WASFindings = () => {
  const { cardRoot, cardSmall, header, body } = RiskStyles.classesRisk;
  const headerFontSize = { fontSize: '1.3rem' };
  return (
    <Paper elevation={0} className={cardRoot}>
      <div className={cardSmall}>
        <div className={header}>
          <h2>WAS High Level Findings</h2>
        </div>
        <div className={body}>
          <Grid container spacing={1}>
            <Grid item xs={12} pb={2}>
              <Typography variant="h6">
                Scan Date: {testData.scanDate}
              </Typography>
            </Grid>
            <Grid item xs={6}>
              <Typography variant="h5" sx={headerFontSize}>
                ACTIVE VULNERABILITIES
              </Typography>
              <Typography variant="h4" color="error">
                {testData.activeVulns}
              </Typography>
              <br />
              <Typography variant="h5" sx={headerFontSize}>
                REOPENED VULNERABILITIES
              </Typography>
              <Typography variant="h4" color="error">
                {testData.reopenedVulns}
              </Typography>
            </Grid>
            <Grid item xs={6}>
              <Typography variant="h5" sx={headerFontSize}>
                NEW VULNERABILITIES
              </Typography>
              <Typography variant="h4" color="error">
                {testData.newVulns}
              </Typography>
              <br />
              <Typography variant="h5" sx={headerFontSize}>
                SENSITIVE CONTENT
              </Typography>
              <Typography variant="h4" color="error">
                {testData.sensitiveContent}
              </Typography>
            </Grid>
          </Grid>
        </div>
      </div>
    </Paper>
  );
};
export default WASFindings;
