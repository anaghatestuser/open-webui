"""add chat list index

Revision ID: b8e4c07f52a1
Revises: a7d3f6b91c24
Create Date: 2026-08-03 12:40:11.882104

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'b8e4c07f52a1'
down_revision: str | None = 'a7d3f6b91c24'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index('user_id_updated_at_id_idx', 'chat', ['user_id', sa.text('updated_at DESC'), 'id'])


def downgrade() -> None:
    op.drop_index('user_id_updated_at_id_idx', table_name='chat')
