from vinfra import exceptions
from vinfra.api import base
from vinfra.api.compute.base import Manager
from vinfra.utils import flatten_args


class VolumeBackupCreateTask(base.PollTask):
    def __init__(self, resource):
        self.resource = resource
        self.backup_id = base.get_id(resource)

    def wait(self, timeout=None):
        timeout = timeout or self.default_timeout
        try:
            resource = super(VolumeBackupCreateTask, self).wait(
                timeout=timeout)
        except exceptions.TimeoutError:
            status = self.resource.status
            msg = (
                "Failed to create volume backup (id={}). Timeout of {} "
                "seconds exceeded (status={}).".format(
                    self.backup_id, timeout, status)
            )
            raise exceptions.TimeoutError(msg)
        return resource

    def poll(self):
        self.resource = self.resource.get()
        if self.resource.status == 'creating':
            return None
        if self.resource.status != 'available':
            msg = (
                "Failed to get volume backup status (status={}).".format(
                    self.resource.status)
            )
            raise exceptions.VinfraError(msg)

        return self.resource

    def get_info(self):
        return self.resource


class VolumeBackupDeleteTask(base.PollTask):
    def __init__(self, manager, resource):
        self.manager = manager
        self.resource = resource
        self.backup_id = base.get_id(resource)

    def wait(self, timeout=None):
        timeout = timeout or self.default_timeout
        try:
            super(VolumeBackupDeleteTask, self).wait(timeout=timeout)
        except exceptions.TimeoutError:
            status = self.resource.get().status
            msg = (
                "Failed to delete volume backup (id={}). Timeout of {} "
                "seconds exceeded (status={})".format
                (self.backup_id, timeout, status)
            )
            raise exceptions.TimeoutError(msg)

    def poll(self):
        backups = self.manager.list()
        for backup in backups:
            if backup.id == self.backup_id:
                return None
        return {}

    def get_info(self):
        return None


class VolumeBackupRestoreTask(base.StatusTask):
    status = 'available'


class VolumeBackup(base.Resource):
    def delete_async(self):
        return self.manager.delete_async(self)

    def delete(self):
        return self.manager.delete(self)

    def restore_async(self, name=None, storage_policy=None):
        return self.manager.restore_async(self, name=name,
                                          storage_policy=storage_policy)

    def restore(self, name=None, storage_policy=None):
        return self.manager.restore(self, name=name,
                                    storage_policy=storage_policy)


class VolumeBackupManager(Manager):
    resource_class = VolumeBackup
    base_url = "/compute/volume_backups"

    def list(self, filters=None):
        return self._list(self.base_url, filters=filters)

    def get(self, backup):
        backup_id = base.get_id(backup)
        return self._get("{}/{}".format(self.base_url, backup_id))

    def create_async(self, volume_id, name=None, description=None):
        payload = dict(
            volume_id=volume_id,
        )
        payload.update(flatten_args(
            name=name,
            description=description,
        ))
        backup = self._post(self.base_url, payload)
        return VolumeBackupCreateTask(backup)

    @base.async_wait
    def create(self, volume_id, name=None, description=None):
        return self.create_async(volume_id,
                                 name=name,
                                 description=description)

    def delete_async(self, backup):
        backup_id = base.get_id(backup)
        self._delete("{}/{}".format(self.base_url, backup_id))
        return VolumeBackupDeleteTask(self, backup)

    @base.async_wait
    def delete(self, backup):
        return self.delete_async(backup)

    def restore_async(self, backup, name=None, storage_policy=None):
        payload = dict()
        if name is not None:
            payload['name'] = name
        if storage_policy is not None:
            payload['storage_policy'] = storage_policy
        url = "{}/{}/restore".format(
            self.base_url, base.get_id(backup)
        )
        self._post(url, payload)
        return VolumeBackupRestoreTask(self, backup)

    @base.async_wait
    def restore(self, backup, name=None, storage_policy=None):
        return self.restore_async(backup, name=name,
                                  storage_policy=storage_policy)
