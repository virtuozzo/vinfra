from vinfra.api import base
from vinfra.api.compute.base import Manager
from vinfra.utils import flatten_args


class BackupPlanVolumeManager(base.Manager):
    def __init__(self, api, compute, backup_plan):
        super(BackupPlanVolumeManager, self).__init__(api)
        self.volumes = compute.volumes
        self.backup_plan_id = base.get_id(backup_plan)
        self.resource_class = compute.volumes.resource_class
        self.base_url = "/compute/backup_plans/{}/volumes".format(
            self.backup_plan_id)

    def add(self, ids):
        self._post(self.base_url, dict(ids=ids))

    def remove(self, ids):
        self._delete(self.base_url, dict(ids=ids))

    def list(self, limit=None, marker=None, filters=None, sort=None):
        filters = filters or {}
        filters['backup_plan_id'] = self.backup_plan_id
        return self.volumes.list(limit=limit, marker=marker, filters=filters, sort=sort)


class BackupPlan(base.Resource):
    def __init__(self, manager, info):
        super(BackupPlan, self).__init__(manager, info)
        self.volumes = BackupPlanVolumeManager(self.manager.api, self.manager.compute, self)

    def update(self, **kwargs):
        return self.manager.update(self, **kwargs)

    def delete(self):
        return self.manager.delete(self)


class BackupPlanManager(Manager):
    resource_class = BackupPlan
    base_url = "/compute/backup_plans"

    def __init__(self, api, compute):
        super(BackupPlanManager, self).__init__(api)
        self.compute = compute

    def _get_marker_from_data(self, data):
        # backup plans API currently has offset as a marker
        return len(data)

    def list(self, limit=None, marker=None, filters=None, sort=None):
        return self._list(self.base_url, limit=limit, marker=marker,
                          filters=filters, sort=sort)

    def get(self, backup):
        backup_id = base.get_id(backup)
        return self._get("{}/{}".format(self.base_url, backup_id))

    def create(self, name=None, description=None, schedule=None,
               properties=None, disabled=None):
        payload = flatten_args(
            name=name,
            description=description,
            disabled=disabled,
            schedule=flatten_args(**schedule) if schedule is not None else None,
            properties=flatten_args(**properties) if properties is not None else None,
        )
        return self._post(self.base_url, payload)

    def update(self, backup_plan, name=None, description=None,
               schedule=None, properties=None, disabled=None):
        backup_plan_id = base.get_id(backup_plan)
        payload = flatten_args(
            name=name,
            description=description,
            disabled=disabled,
            schedule=flatten_args(**schedule) if schedule is not None else None,
            properties=flatten_args(**properties) if properties is not None else None,
        )
        return self._patch("{}/{}".format(
            self.base_url, backup_plan_id), payload)

    def delete(self, backup_plan):
        backup_plan_id = base.get_id(backup_plan)
        self._delete("{}/{}".format(self.base_url, backup_plan_id))
