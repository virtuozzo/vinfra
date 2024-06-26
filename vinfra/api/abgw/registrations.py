from vinfra.api import base


class AbgwRegistration(base.Resource):

    @property
    def base_url(self):
        return "/{}/abgw/registrations/{}".format(
            base.get_id(self.manager.cluster), base.get_id(self)
        )

    def update(
            self,
            name=None,  # type: str
            address=None,  # type: str
            username=None,  # type: str
            password=None,  # type: str
    ):
        data = {}
        if name is not None:
            data['name'] = name
        if address is not None:
            data['address'] = address
        if username is not None:
            data['username'] = username
        log = True
        if password is not None:
            data['password'] = password
            log = False
        return self.manager.client.patch_async(self.base_url, json=data, log=log)

    def delete(
            self,
            username=None,  # type: str
            password=None,  # type: str
            force=False,  # type: bool
    ):
        data = {}
        if force:
            data['force'] = force

        log = True
        if username and password:
            data = {
                'username': username,
                'password': password,
            }
            log = False
        return self.manager.client.delete_async(self.base_url, json=data, log=log)


class AbgwRegistrationsApi(base.Manager):

    resource_class = AbgwRegistration

    def __init__(self, cluster):
        self.cluster = cluster
        super(AbgwRegistrationsApi, self).__init__(cluster.manager.api)

    @property
    def base_url(self):
        return "/{}/abgw/registrations".format(base.get_id(self.cluster))

    def create_async(
            self,
            name,  # type: str
            address,  # type: str
            account_server,  # type: str
            username,  # type: str
            password,  # type: str
            location=None,  # type: str
            primary_storage_id=None,  # type: str
            failback_storage_id=None,  # type: str
    ):
        data = {
            'name': name,
            'address': address,
            'account_server': account_server,
            'username': username,
            'password': password,
        }
        if location is not None:
            data['location'] = location
        if primary_storage_id is not None:
            data['primary_storage_id'] = primary_storage_id
        if failback_storage_id is not None:
            data['failback_storage_id'] = failback_storage_id
        return self.client.post_async(self.base_url, json=data, log=False)

    def import_async(self, infile):
        # infile is a stream
        url = "/{}/import/".format(self.base_url)
        headers = {
            'Content-Type': 'application/octet-stream',
        }
        return self.client.post_async(
            url,
            headers=headers,
            data=infile
        )

    def create_true_image_async(
            self,
            name,  # type: str
            address,  # type: str
            revocation_url,  # type: str
            archived_certificates_chain,  # type: stream
    ):
        headers = {
            'x-hci-true-image-name': name,
            'x-hci-true-image-address': address,
            'x-hci-true-image-revocation-url': revocation_url,
            'Content-Type': 'application/octet-stream',
        }
        url = "/{}/abgw/true-image/registrations".format(
            base.get_id(self.cluster))
        return self.client.post_async(
            url,
            headers=headers,
            data=archived_certificates_chain
        )

    def get(
            self,
            registration,  # type: AbgwRegistration
    ):
        registration_id = base.get_id(registration)
        return self._get("{}/{}".format(self.base_url, registration_id))

    def export(
            self,
            registration,  # type: AbgwRegistration
            fdst
    ):

        stream = self.client.send_request_raw(
            method="get",
            url="{}/{}/export/".format(self.base_url, base.get_id(registration)),
            stream=True
        )

        for chunk in stream:
            fdst.write(chunk)

    def list(self):
        return self._list(self.base_url)

    def renew_true_image_certificates(
            self,
            registration,
            archived_certificates_chain  # type: stream
    ):
        url = "/{}/abgw/true-image/registrations/{}".format(
            base.get_id(self.cluster),
            base.get_id(registration)
        )
        headers = {
            'Content-Type': 'application/octet-stream',
        }
        return self.client.put_async(
            url,
            headers=headers,
            data=archived_certificates_chain
        )

    def renew_certificates(
            self,
            registration,
            username,  # type: str
            password,  # type: str
            server_cert_only=False,  # type: bool
    ):
        registration_id = base.get_id(registration)
        data = {
            'username': username,
            'password': password,
        }
        if server_cert_only:
            data['server_cert_only'] = server_cert_only

        url = "{}/{}/renew".format(self.base_url, registration_id)
        return self.client.post_async(url, json=data, log=False)
