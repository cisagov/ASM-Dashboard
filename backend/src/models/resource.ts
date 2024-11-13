import {
  BaseEntity,
  Column,
  Entity,
  ManyToMany,
  ManyToOne,
  JoinTable,
  PrimaryGeneratedColumn
} from 'typeorm';
import { Question } from './question';

@Entity()
export class Resource extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  description: string;

  @Column()
  name: string;

  @Column()
  type: string;

  @Column({ unique: true })
  url: string;

  @ManyToMany(() => Question, (question) => question.resources)
  @JoinTable({
    name: 'question_resources_resource',
    joinColumn: {
      name: 'question_id',
      referencedColumnName: 'id'
    },
    inverseJoinColumn: {
      name: 'resource_id',
      referencedColumnName: 'id'
    }
  })
  questions: Question[];
}
