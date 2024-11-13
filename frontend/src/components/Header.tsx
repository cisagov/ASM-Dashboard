import React, { FC } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { styled } from '@mui/material/styles';
import { useAuthContext } from 'context';
import {
  useUserLevel,
  GLOBAL_ADMIN,
  REGIONAL_ADMIN,
  STANDARD_USER
} from 'hooks/useUserLevel';
import { matchPath } from 'utils/matchPath';
import { AppBar, Toolbar, IconButton, Box, Typography } from '@mui/material';
import { ChevronLeft, FilterAlt } from '@mui/icons-material';
import { useTheme } from '@mui/system';
import { NavItem } from './NavItem';
import { UserMenu } from './UserMenu';
import logo from '../assets/cyhydashboard.svg';
import cisaLogo from '../assets/cisaSeal.svg';

const Root = styled('div')(() => ({}));

interface NavItemType {
  title: string | JSX.Element;
  path: string;
  users?: number;
  onClick?: any;
  exact: boolean;
}

interface MenuItemType {
  title: string;
  path: string;
  users?: number;
  onClick?: any;
  exact: boolean;
}

interface HeaderProps {
  isFilterDrawerOpen: boolean;
  setIsFilterDrawerOpen: (isFilterDrawerOpen: boolean) => void;
}

export const Header: React.FC<HeaderProps> = ({
  isFilterDrawerOpen,
  setIsFilterDrawerOpen
}) => {
  const { pathname } = useLocation();
  const { user, logout } = useAuthContext();
  const theme = useTheme();

  const { userLevel, formattedUserType } = useUserLevel();

  const navItems: NavItemType[] = [
    {
      title: 'Overview',
      path: '/',
      users: STANDARD_USER,
      exact: true
    },
    {
      title: 'Inventory',
      path: '/inventory',
      users: STANDARD_USER,
      exact: false
    }
  ].filter(({ users }) => users <= userLevel);

  const userMenuItems: MenuItemType[] = [
    {
      title: 'Admin Tools',
      path: '/admin-tools',
      users: GLOBAL_ADMIN,
      exact: true
    },
    {
      title: 'User Registration',
      path: '/region-admin-dashboard',
      users: REGIONAL_ADMIN,
      exact: true
    },
    {
      title: 'Manage Organizations',
      path: '/organizations',
      users: REGIONAL_ADMIN,
      exact: true
    },
    {
      title: 'Manage Users',
      path: '/users',
      users: REGIONAL_ADMIN,
      exact: true
    },
    {
      title: 'My Settings',
      path: '/settings',
      users: STANDARD_USER,
      exact: true
    },
    {
      title: 'Logout',
      path: '/settings',
      users: STANDARD_USER,
      onClick: logout,
      exact: true
    }
  ].filter(({ users }) => users <= userLevel);

  // const orgPageMatch = useRouteMatch('/organizations/:id');

  const desktopNavItems: JSX.Element[] = navItems.map((item) => (
    <NavItem key={item.title.toString()} {...item} />
  ));

  return (
    <Root>
      <AppBar position="static" elevation={0}>
        <Box
          maxWidth="1440px"
          display="flex"
          width="100%"
          height="100%"
          margin="0 auto"
          flexWrap="wrap"
          alignItems="center"
        >
          <Toolbar sx={{ width: '100%', display: 'flex' }}>
            <Box
              display="flex"
              flexDirection="row"
              width="100%"
              alignItems="center"
            >
              {matchPath(['/', '/inventory'], pathname) && user ? (
                <FilterDrawerButton
                  open={isFilterDrawerOpen}
                  setOpen={setIsFilterDrawerOpen}
                />
              ) : (
                <></>
              )}
              <img
                src={cisaLogo}
                style={{
                  height: 40,
                  marginRight: theme.spacing(1)
                }}
                alt="Cybersecurity and Infrastructure Security Agency Logo"
              />
              <Link to="/" style={{ width: 'min-content', height: '30px' }}>
                <img
                  src={logo}
                  style={{
                    width: 175,
                    maxWidth: 175,
                    padding: theme.spacing(),
                    paddingLeft: 0
                  }}
                  alt="CyHy Dashboard Icon Navigate Home"
                />
              </Link>
              <Box
                width="max-content"
                sx={{
                  display: { xs: 'none', sm: 'none', md: 'flex' }
                }}
              >
                {desktopNavItems}
              </Box>
            </Box>
            {userLevel > 0 && (
              <Box
                sx={{ display: { xs: 'none', sm: 'none', md: 'flex' } }}
                textTransform="uppercase"
                width="auto"
                minWidth="max-content"
              >
                <Typography>{formattedUserType}</Typography>
              </Box>
            )}

            <Box
              display="flex"
              flexDirection="row"
              width="100%"
              justifyContent="end"
            >
              {userLevel > 0 && (
                <UserMenu userMenuItems={userMenuItems} navItems={navItems} />
              )}
            </Box>
          </Toolbar>
        </Box>
      </AppBar>
    </Root>
  );
};

interface FilterDrawerButtonProps {
  open: boolean;
  setOpen: (open: boolean) => void;
}

const FilterDrawerButton: FC<FilterDrawerButtonProps> = ({ open, setOpen }) => {
  return (
    <IconButton
      onClick={() => setOpen(!open)}
      aria-label={open ? 'Close filter drawer' : 'Open filter drawer'}
    >
      {open ? (
        <ChevronLeft style={{ color: 'white' }} />
      ) : (
        <FilterAlt style={{ color: 'white' }} />
      )}
    </IconButton>
  );
};
