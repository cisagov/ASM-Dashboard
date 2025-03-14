import React, { useState } from 'react';
import { useHistory } from 'react-router-dom';
import { classes, StyledPaper } from './Styling/resultCardStyle';
import clsx from 'classnames';
import { Result } from '../../context/SearchProvider';
// @ts-ignore:next-line
import { parseISO, formatDistanceToNow } from 'date-fns';
import DOMPurify from 'dompurify';

// Sync this with the backend client in es-client.ts.
export interface WebpageRecord {
  webpage_id: string;
  webpage_createdAt: Date;
  webpage_updatedAt: Date;
  webpage_syncedAt: Date;
  webpage_lastSeen: Date;
  webpage_s3Key: string;
  webpage_url: string;
  webpage_status: string | number;
  webpage_domainId: string;
  webpage_discoveredById: string;

  // Added before elasticsearch insertion (not present in the database):
  suggest?: { input: string | string[]; weight: number }[];
  parent_join?: {
    name: 'webpage';
    parent: string;
  };
  webpage_body?: string;
}

interface Highlight {
  webpage_body: string[];
}

interface Props extends Result {
  onDomainSelected(domainId: string): void;
  selected?: boolean;
  inner_hits?: {
    webpage?: {
      hits: {
        hits: { _source: WebpageRecord; highlight: Highlight }[];
        max_score: number;
        total: {
          value: number;
          relation: string;
        };
      };
    };
  };
}

const filterExpanded = (
  data: any[],
  isExpanded: boolean,
  count: number = 3
) => {
  return isExpanded ? data : data.slice(0, count);
};

export const ResultCard: React.FC<Props> = (props) => {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const {
    id,
    name,
    ip,
    updatedAt,
    services,
    vulnerabilities,
    inner_hits,
    onDomainSelected
  } = props;

  const toggleExpanded = (key: string) => {
    setExpanded((expanded) => ({
      ...expanded,
      [key]: expanded[key] ? !expanded[key] : true
    }));
  };

  let lastSeen;

  const history = useHistory();
  try {
    lastSeen = formatDistanceToNow(parseISO(updatedAt.raw));
  } catch (e) {
    lastSeen = '';
  }

  const onClick = () => {
    onDomainSelected(id.raw);
    history.push(`/inventory/domain/${id.raw}`);
  };

  const ports = services.raw.reduce(
    (acc, nextService) => [...acc, nextService.port],
    []
  );

  const products = services.raw.reduce(
    (acc, nextService) => [
      ...acc,
      ...nextService.products.map(
        (p: any) => `${p.name}${p.version ? ' ' + p.version : ''}`
      )
    ],
    []
  );

  const cves = vulnerabilities.raw.reduce(
    (acc, nextVuln) => [...acc, nextVuln.cve],
    []
  );

  const data = [];
  if (products.length > 0) {
    data.push({
      label: `Product${products.length > 1 ? 's' : ''}`,
      count: products.length,
      value: filterExpanded(
        [...Array.from(new Set(products))],
        Boolean(expanded.products),
        8
      ).join(', '),
      onExpand: () => toggleExpanded('products'),
      expansionText:
        products.length <= 8 ? null : expanded.products ? 'less' : 'more'
    });
  }
  if (cves.length > 0) {
    data.push({
      label: `CVE${cves.length > 1 ? 's' : ''}`,
      count: cves.length,
      value: filterExpanded(cves, Boolean(expanded.vulns), 10).join(', '),
      onExpand: () => toggleExpanded('vulns'),
      expansionText: cves.length <= 10 ? null : expanded.vulns ? 'less' : 'more'
    });
  }
  if (inner_hits?.webpage?.hits?.hits?.length! > 0) {
    const { hits } = inner_hits!.webpage!.hits!;
    data.push({
      label: `matching webpage${hits.length > 1 ? 's' : ''}`,
      count: hits.length,
      value: hits.map((e, idx) => (
        <React.Fragment key={idx}>
          <small>
            <strong>{e._source.webpage_url}</strong>
            <br />
            {e.highlight?.webpage_body?.map((body, idx) => (
              <React.Fragment key={idx}>
                <code
                  dangerouslySetInnerHTML={{
                    __html: DOMPurify.sanitize(body, { ALLOWED_TAGS: ['em'] })
                  }}
                />
              </React.Fragment>
            ))}
          </small>
        </React.Fragment>
      ))
    });
  }

  return (
    <StyledPaper
      elevation={0}
      classes={{ root: classes.root }}
      aria-label="view domain details"
    >
      <div className={classes.inner} onClick={onClick}>
        <button className={classes.domainRow}>
          <h4>{name.raw}</h4>
          <div className={classes.lastSeen}>
            <span className={classes.label}>Last Seen</span>
            <span className={classes.data}>{lastSeen} ago</span>
          </div>
        </button>

        {ip.raw && (
          <div className={clsx(classes.ipRow, classes.row)}>
            <div>
              <span className={classes.label}>IP</span>
              <span className={classes.data}>{ip.raw}</span>
            </div>
            {ports.length > 0 && (
              <div className={classes.lastSeen}>
                <span className={classes.label}>
                  <span className={classes.count}>{ports.length}</span>
                  {` Port${ports.length > 1 ? 's' : ''}`}
                </span>
                <span className={classes.data}>{ports.join(', ')}</span>
              </div>
            )}
          </div>
        )}

        {data.map(({ label, value, count, onExpand, expansionText }) => (
          <p className={classes.row} key={label}>
            <span className={classes.label}>
              {count !== undefined && (
                <span className={classes.count}>{count} </span>
              )}
              {label}
            </span>
            <span className={classes.data}>
              {value}
              {expansionText && (
                <button
                  className={classes.expandMore}
                  onClick={(event) => {
                    event.stopPropagation();
                    if (onExpand) onExpand();
                  }}
                >
                  {expansionText}
                </button>
              )}
            </span>
          </p>
        ))}
      </div>
    </StyledPaper>
  );
};
