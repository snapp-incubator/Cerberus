<h1 align="center">Cerberus</h1>

<p align="center">
    <img alt="Cerberus" src="./docs/asssets/imgs/cerberus.webp">
    <br />
    <img alt="GitHub Workflow Status (with event)" src="https://img.shields.io/github/actions/workflow/status/snapp-incubator/Cerberus/test.yml?style=for-the-badge&logo=github&label=test">
    <img alt="GitHub Workflow Status (with event)" src="https://img.shields.io/github/actions/workflow/status/snapp-incubator/Cerberus/release.yml?style=for-the-badge&logo=github&label=release">
    <img alt="GitHub tag (with filter)" src="https://img.shields.io/github/v/tag/snapp-incubator/Cerberus?style=for-the-badge&logo=git">
    <img alt="GitHub go.mod Go version (subdirectory of monorepo)" src="https://img.shields.io/github/go-mod/go-version/snapp-incubator/Cerberus?style=for-the-badge&logo=go">
</p>

In the dynamic landscape of modern application deployment and microservices architecture, the need for secure and controlled access to services is paramount. Cerberus is a powerful authorization server, seamlessly integrates with [Contour](https://projectcontour.io/)., leveraging the [External Authorization interface](https://projectcontour.io/guides/external-authorization/) of [Envoy](https://www.envoyproxy.io/), to provide a dynamic and flexible access control solution. It implements [auth_ext](https://www.envoyproxy.io/docs/envoy/v1.28.0/api-v3/service/auth/v3/external_auth.proto.html) gRPC interface which is envoy's standard and it is even a defacto of microservices.

## Getting Started

You’ll need a Kubernetes cluster to run against. You can use [KIND](https://sigs.k8s.io/kind) to get a local cluster for testing, or run against a remote cluster.
**Note:** Your controller will automatically use the current context in your kubeconfig file (i.e. whatever cluster `kubectl cluster-info` shows).

### Running on the cluster

1. Install Instances of Custom Resources:

```sh
kubectl apply -f config/samples/
```

2. Build and push your image to the location specified by `IMG`:

```sh
make docker-build docker-push IMG=<some-registry>/cerberus:tag
```

3. Deploy the controller to the cluster with the image specified by `IMG`:

```sh
make deploy IMG=<some-registry>/cerberus:tag
```

### Uninstall CRDs

To delete the CRDs from the cluster:

```sh
make uninstall
```

### Undeploy controller

UnDeploy the controller from the cluster:

```sh
make undeploy
```

## Contributing

// TODO(user): Add detailed information on how you would like others to contribute to this project

### How it works

- **Contour** is a modern Kubernetes ingress controller that facilitates the routing of external traffic to internal services. It plays a crucial role in managing ingress traffic and ensuring efficient communication within a microservices environment. It employs Envoy as its backend.
Contour provides a wide range of features, including external authorization. This feature enables the delegation of authorization decisions to an external service, proving to be more flexible and scalable compared to relying solely on Contour's built-in authorization methods. An external authorization server, in this context, is a server implementing the Envoy external authorization gRPC protocol. Notably, Contour seamlessly supports any server that adopts this protocol, fostering adaptability and choice in implementing robust authorization solutions.
- **Envoy** is a high-performance proxy designed for microservices architectures. It functions as the data plane for Contour, handling communication between services and providing features like load balancing, service discovery, and security.

Cerberus acts as a robust authorization server, complementing the capabilities of Contour and Envoy. By implementing the auth gRPC interface of Envoy, Cerberus seamlessly integrates with the microservices ecosystem, ensuring secure and controlled access to services. It's a part of External Authorization ability described in Contour Project.

![The San Juan Mountains are beautiful!](./docs/asssets/imgs/sequence.png)

This project aims to follow the Kubernetes [Operator Pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/). It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/), which provide a reconcile function responsible for synchronizing resources until the desired state is reached on the cluster.



### Test It Out

1. Install the CRDs into the cluster:

```sh
make install
```

2. Run your controller (this will run in the foreground, so switch to a new terminal if you want to leave it running):

```sh
make run
```

**NOTE:** You can also run this in one step by running: `make install run`

### Modifying the API definitions

If you are editing the API definitions, generate the manifests such as CRs or CRDs using:

```sh
make manifests
```

**NOTE:** Run `make --help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
