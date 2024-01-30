package auth

//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens/status,verbs=get;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices/status,verbs=get;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webserviceaccountbindings,verbs=get;list;watch;
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webserviceaccountbindings/status,verbs=get;
//+kubebuilder:rbac:groups="",namespace='cerberus-operator-system',resources=secrets,verbs=get;list;watch;create;update;patch;delete
