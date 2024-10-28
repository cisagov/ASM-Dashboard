import React from 'react';
import { NavLink, useHistory } from 'react-router-dom';
import { useUserLevel } from 'hooks/useUserLevel';
import {
  Box,
  Button,
  Divider,
  IconButton,
  Menu,
  MenuItem
} from '@mui/material';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';
import MenuIcon from '@mui/icons-material/Menu';

interface MenuItemType {
  title: string;
  path: string;
  users?: number;
  exact: boolean;
  onClick?: any;
}
interface NavItemType {
  title: string | JSX.Element;
  path: string;
  users?: number;
  onClick?: any;
  exact: boolean;
}

interface Props {
  userMenuItems: MenuItemType[];
  navItems: NavItemType[];
}

export const UserMenu: React.FC<Props> = (props) => {
  const { userMenuItems, navItems } = props;
  const history = useHistory();
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);
  const { formattedUserType } = useUserLevel();
  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };

  return (
    <Box ml={2}>
      <Button
        sx={{
          display: { xs: 'none', sm: 'none', md: 'flex' },
          color: 'white'
        }}
        startIcon={<AccountCircleIcon />}
        endIcon={<ArrowDropDownIcon />}
        onClick={handleClick}
      >
        My Account
      </Button>
      <IconButton
        sx={{
          display: { xs: 'flex', sm: 'flex', md: 'none' },
          color: 'white'
        }}
        onClick={handleClick}
      >
        <MenuIcon />
      </IconButton>
      <Menu anchorEl={anchorEl} open={open} onClose={handleClose}>
        <Box
          sx={{ display: { xs: 'block', sm: 'block', md: 'none' } }}
          textTransform="uppercase"
        >
          <MenuItem sx={{ justifyContent: 'center' }}>
            {formattedUserType}
          </MenuItem>
          <Divider />
        </Box>
        {navItems.map((item, index) => (
          <MenuItem
            sx={{
              display: { xs: 'flex', sm: 'flex', md: 'none' }
            }}
            key={index}
            component={NavLink}
            to={item.path}
            selected={item.path === history.location.pathname}
          >
            {item.title}
          </MenuItem>
        ))}
        {userMenuItems.map((item, index) => (
          <MenuItem
            key={index}
            component={NavLink}
            to={item.onClick ? '#' : item.path}
            selected={
              !item.onClick ? item.path === history.location.pathname : false
            }
            onClick={() => {
              if (item.onClick) {
                item.onClick();
              }
            }}
          >
            {item.title}
          </MenuItem>
        ))}
      </Menu>
    </Box>
  );
};
