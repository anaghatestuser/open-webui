"""add chat timer_at

Revision ID: a7d3f6b91c24
Revises: 6d09d1bf1f23
Create Date: 2026-08-03 10:12:44.190283

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'a7d3f6b91c24'
down_revision: str | None = '6d09d1bf1f23'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('chat', sa.Column('timer_at', sa.BigInteger(), nullable=True))
    op.create_index(
        'timer_at_idx',
        'chat',
        ['timer_at'],
        sqlite_where=sa.text('timer_at IS NOT NULL'),
        postgresql_where=sa.text('timer_at IS NOT NULL'),
    )

    # Timers created before this migration carry their due time in meta only, and would never fire.
    chat = sa.table(
        'chat', sa.column('id', sa.String), sa.column('meta', sa.JSON), sa.column('timer_at', sa.BigInteger)
    )
    conn = op.get_bind()
    pending = conn.execute(
        sa.select(chat.c.id, chat.c.meta)
        .where(chat.c.meta['type'].as_string() == 'timer')
        .where(chat.c.meta['status'].as_string() == 'pending')
    ).all()
    for chat_id, meta in pending:
        try:  # imported chats can carry any meta, and a non-numeric due time must not abort the migration
            due_at = int(meta.get('timer_at'))
        except (TypeError, ValueError):
            continue
        conn.execute(chat.update().where(chat.c.id == chat_id).values(timer_at=due_at))


def downgrade() -> None:
    op.drop_index('timer_at_idx', table_name='chat')
    op.drop_column('chat', 'timer_at')
