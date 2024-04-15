import React from 'react';
import { useParams } from 'react-router-dom';
import Box from '@mui/material/Box';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import Divider from '@mui/material/Divider';
import { RSCNavItem } from './RSCNavItem';

interface Props {
  categories: Categories[];
}

export interface Categories {
  name: string;
}

export const RSCSideNav: React.FC<Props> = ({ categories }) => {
  const { id } = useParams<{ id: string }>();

  return (
    <div>
      <Box sx={{ width: '100%', maxWidth: 360, bgcolor: 'background.paper' }}>
        <List>
          <ListItem>Welcome User</ListItem>
          <Divider component="li" />
          {categories.map((category, index) => (
            <RSCNavItem key={index} name={category.name} />
          ))}
          <ListItem>Take Questionnaire Again</ListItem>
          <Divider component="li" />
          <ListItem>Logout</ListItem>
        </List>
      </Box>
    </div>
  );
};
