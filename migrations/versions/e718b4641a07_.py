"""empty message

Revision ID: e718b4641a07
Revises: cd455d1352e1
Create Date: 2024-03-01 17:38:26.516385

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e718b4641a07'
down_revision = 'cd455d1352e1'
branch_labels = None
depends_on = None


from sqlalchemy.engine.reflection import Inspector

def upgrade():
    # Use SQLAlchemy to inspect the table and check if the column exists
    inspector = Inspector.from_engine(op.get_bind())
    columns = inspector.get_columns('intake_transaction')
    item_name_column_exists = any(column['name'] == 'item_name' for column in columns)

    # If the column doesn't exist, add it
    if not item_name_column_exists:
        with op.batch_alter_table('intake_transaction', schema=None) as batch_op:
            batch_op.add_column(sa.Column('item_name', sa.String(length=50), nullable=True))


def downgrade():
    with op.batch_alter_table('intake_transaction', schema=None) as batch_op:
        batch_op.drop_column('item_name')
