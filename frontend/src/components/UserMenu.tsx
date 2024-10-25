import React from 'react';
import { useHistory } from 'react-router-dom';
import { Box, Button, Divider, Menu, MenuItem } from '@mui/material';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';
import { useAuthContext } from 'context';
import { useUserLevel } from 'hooks/useUserLevel';

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
  const { userMenuItems } = props;
  const { user } = useAuthContext();
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
  const handleNavigate = (path: string) => {
    handleClose();
    history.push(path);
  };
  // const filteredMenuItems = userMenuItems.filter((item) => {
  //   const userType = user?.userType;
  //   const userAccessLevel = item.users ?? 0;
  //   return (
  //     userType === 'globalAdmin' ||
  //     ((userType === 'regionalAdmin' || userType === 'globalView') &&
  //       userAccessLevel <= 2) ||
  //     userAccessLevel <= 1
  //   );
  // });
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
      <Button
        sx={{
          display: { xs: 'flex', sm: 'flex', md: 'none' },
          color: 'white'
        }}
        startIcon={<AccountCircleIcon />}
        onClick={handleClick}
      />
      <Menu anchorEl={anchorEl} open={open} onClose={handleClose}>
        <Box sx={{ display: { xs: 'block', sm: 'block', md: 'none' } }}>
          <MenuItem sx={{ justifyContent: 'center' }}>
            {formattedUserType}
          </MenuItem>
          <Divider />
        </Box>
        {props.navItems.map((item, index) => (
          <>
            <MenuItem
              sx={{ display: { xs: 'block', sm: 'block', md: 'none' } }}
              key={index}
              onClick={() => handleNavigate(item.path)}
            >
              {item.title}
            </MenuItem>
          </>
        ))}
        {userMenuItems.map((item, index) => (
          <MenuItem key={index} onClick={() => handleNavigate(item.path)}>
            {item.title}
          </MenuItem>
        ))}
      </Menu>
    </Box>
  );
};
