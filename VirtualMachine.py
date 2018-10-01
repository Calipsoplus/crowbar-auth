from app import db, ma


class VirtualMachine(db.Model):
    ip = db.Column(db.String(15), primary_key=True)
    hostname = db.Column(db.String(50))
    owner = db.Column(db.String(50))


class VirtualMachineSchema(ma.ModelSchema):
    class Meta:
        fields = ['hostname', 'ip']
