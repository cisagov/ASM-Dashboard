import React from 'react';
import { ResponsiveBar } from '@nivo/bar';
import { Point } from './Risk';
import { useHistory } from 'react-router-dom';
import * as RiskStyles from './style';
import { Paper } from '@mui/material';
import { scaleLinear } from 'd3-scale';

const TopVulnerablePorts = (props: { data: Point[] }) => {
  const history = useHistory();
  const { data } = props;
  const { cardRoot, cardSmall, header, chartSmall } = RiskStyles.classesRisk;
  const dataVal = data.map((e) => ({ ...e, [['Port'][0]]: e.value })) as any;

  const getMinMaxPort = (data: any[]): [number, number] => {
    const ports = data
      .filter((item) => item.Port !== null)
      .map((item: { Port: any }) => item.Port);
    const minPort = Math.min(...ports);
    const maxPort = Math.max(...ports);
    return [minPort, maxPort];
  };
  const colorScale = scaleLinear<string>()
    .domain(getMinMaxPort(dataVal))
    .range(['#7BC9FF', '#135787']);

  return (
    <Paper elevation={0} className={cardRoot}>
      <div className={cardSmall}>
        <div className={header}>
          <h2>Most Common Ports</h2>
        </div>
        <div className={chartSmall}>
          <ResponsiveBar
            data={dataVal}
            colors={({ value }) => colorScale(value ?? 0)}
            keys={['Port']}
            value="value"
            layers={['grid', 'axes', 'bars', 'markers', 'legends']}
            indexBy="label"
            margin={{ top: 30, right: 40, bottom: 75, left: 100 }}
            theme={{
              fontSize: 12,
              axis: {
                legend: {
                  text: {
                    fontWeight: 'bold'
                  }
                }
              }
            }}
            onClick={(event) => {
              history.push(
                `/inventory?filters[0][field]=services.port&filters[0][values][0]=n_${event.data.label}_n&filters[0][type]=any`
              );
              window.location.reload();
            }}
            padding={0.5}
            borderColor={{ from: 'color', modifiers: [['darker', 1.6]] }}
            axisTop={null}
            axisRight={null}
            axisBottom={{
              tickSize: 0,
              tickPadding: 5,
              tickRotation: 0,
              legend: 'Port',
              legendPosition: 'middle',
              legendOffset: 40
            }}
            axisLeft={{
              tickSize: 0,
              tickPadding: 20,
              tickRotation: 0,
              legend: 'Count',
              legendPosition: 'middle',
              legendOffset: -65
            }}
            animate={true}
            enableLabel={false}
            motionDamping={15}
            enableGridX={false}
            enableGridY={true}
            {...({ motionStiffness: 90 } as any)}
          />
        </div>
      </div>
    </Paper>
  );
};
export default TopVulnerablePorts;
