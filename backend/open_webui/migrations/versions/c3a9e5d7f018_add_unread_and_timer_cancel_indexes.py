"""add unread and timer cancel indexes

Revision ID: c3a9e5d7f018
Revises: b8e4c07f52a1
Create Date: 2026-08-03 14:05:32.407518

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c3a9e5d7f018'
down_revision: str | None = 'b8e4c07f52a1'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        'user_id_timer_at_idx',
        'chat',
        ['user_id', 'timer_at'],
        sqlite_where=sa.text('timer_at IS NOT NULL'),
        postgresql_where=sa.text('timer_at IS NOT NULL'),
    )
    op.create_index(
        'user_id_folder_unread_idx',
        'chat',
        ['user_id', 'folder_id', 'archived', 'updated_at', 'last_read_at', 'id'],
    )
    op.create_index('chat_message_chat_role_done_idx', 'chat_message', ['chat_id', 'role', 'done'])


def downgrade() -> None:
    op.drop_index('chat_message_chat_role_done_idx', table_name='chat_message')
    op.drop_index('user_id_folder_unread_idx', table_name='chat')
    op.drop_index('user_id_timer_at_idx', table_name='chat')
