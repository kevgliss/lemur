"""empty message

Revision ID: f62f5a1b6717
Revises: b29e2c4bf8c9
Create Date: 2017-10-03 10:56:23.153777

"""

# revision identifiers, used by Alembic.
revision = 'f62f5a1b6717'
down_revision = 'b29e2c4bf8c9'

from alembic import op
import sqlalchemy as sa
from sqlalchemy_utils.types import TSVectorType
from sqlalchemy_searchable import sync_trigger


def upgrade():
    conn = op.get_bind()
    op.add_column('certificates', sa.Column('search_vector', TSVectorType(), nullable=True))
    op.create_index('ix_certificates_search_vector', 'certificates', ['search_vector'], unique=False, postgresql_using='gin')
    sync_trigger(conn, 'certificates', 'search_vector', ['name', 'owner', 'cn', 'signing_algorithm'])


def downgrade():
    conn = op.get_bind()
    op.drop_index('ix_certificates_search_vector', table_name='certificates')
    op.drop_column('certificates', 'search_vector')
    sync_trigger(conn, 'certificates', 'search_vector', ['name', 'owner', 'cn', 'signing_algorithm'])
