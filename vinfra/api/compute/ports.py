from vinfra.api import base
from vinfra.api.compute.base import Manager

class Port(base.Resource):
    pass

class PortManager(Manager):
    resource_class = Port

    def list(self, limit=None, marker=None, filters=None, sort=None):
        """List all ports."""
        return self._list('/compute/ports',
                          limit=limit,
                          marker=marker,
                          filters=filters,
                          sort=sort)

    def create(self, **kwargs):
        """Create a port."""
        payload = {}
        payload.update(kwargs)
        return self._post('/compute/ports', json=payload)

    def show(self, port_id):
        """Get a specific port."""
        url = '/compute/ports/{}'.format(port_id)
        return self._get(url)

    def delete(self, port_id):
        """Delete a specific port."""
        url = '/compute/ports/{}'.format(port_id)
        return self._delete(url)

    def update(self, port_id, **kwargs):
        """Update a port."""
        payload = {}
        payload.update(kwargs)
        url = '/compute/ports/{}'.format(port_id)
        return self._put(url, json=payload)
