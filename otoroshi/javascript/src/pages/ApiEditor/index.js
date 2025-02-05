import React, { useEffect, useRef, useState } from 'react'

import './index.scss'

import { API_STATE } from './model';
import Sidebar from './Sidebar';
import { Link, Switch, Route, useParams, useHistory } from 'react-router-dom';
import { Uptime } from '../../components/Status';
import { Form, Table } from '../../components/inputs';
import { v4 as uuid, v4 } from 'uuid';
import Designer, { BackendSelector } from '../RouteDesigner/Designer';
import Loader from '../../components/Loader';
import { dynamicTitleContent } from '../../components/DynamicTitleSignal';
import PageTitle from '../../components/PageTitle';
import { FeedbackButton } from '../RouteDesigner/FeedbackButton';
import { nextClient } from '../../services/BackOfficeServices';
import { QueryClient, QueryClientProvider, useQuery } from 'react-query';
import { Button } from '../../components/Button';
import NgBackend from '../../forms/ng_plugins/NgBackend';
import { NgCodeRenderer, NgForm, NgSelectRenderer } from '../../components/nginputs';
import { BackendForm } from '../RouteDesigner/BackendNode';
import NgFrontend from '../../forms/ng_plugins/NgFrontend';

import moment from 'moment';
import { ApiStats } from './ApiStats';

const queryClient = new QueryClient({
    queries: {
        retry: false,
        refetchOnWindowFocus: false
    },
});

const RouteWithProps = ({ component: Component, ...rest }) => (
    <Route
        {...rest}
        component={(routeProps) => <Component {...routeProps} {...rest.props} />}
    />
);

export default function ApiEditor(props) {
    return <div className='editor'>
        <SidebarComponent {...props} />
        <QueryClientProvider client={queryClient}>
            <Switch>
                <RouteWithProps exact path='/apis/:apiId/routes' component={Routes} props={props} />
                <RouteWithProps exact path='/apis/:apiId/routes/new' component={NewRoute} props={props} />
                <RouteWithProps exact path='/apis/:apiId/routes/:routeId/:action' component={RouteDesigner} props={props} />

                <RouteWithProps exact path='/apis/:apiId/consumers' component={Consumers} props={props} />
                <RouteWithProps exact path='/apis/:apiId/consumers/new' component={NewConsumer} props={props} />
                <RouteWithProps exact path='/apis/:apiId/consumers/:consumerId/:action' component={ConsumerDesigner} props={props} />

                <RouteWithProps exact path='/apis/:apiId/subscriptions' component={Subscriptions} props={props} />
                <RouteWithProps exact path='/apis/:apiId/subscriptions/new' component={NewSubscription} props={props} />
                <RouteWithProps exact path='/apis/:apiId/subscriptions/:subscriptionId/:action' component={SubscriptionDesigner} props={props} />

                <RouteWithProps exact path='/apis/:apiId/flows' component={Flows} props={props} />
                <RouteWithProps exact path='/apis/:apiId/flows/new' component={NewFlow} props={props} />
                <RouteWithProps exact path='/apis/:apiId/flows/:flowId/:action' component={FlowDesigner} props={props} />

                <RouteWithProps exact path='/apis/:apiId/backends' component={Backends} props={props} />
                <RouteWithProps exact path='/apis/:apiId/backends/new' component={NewBackend} props={props} />
                <RouteWithProps exact path='/apis/:apiId/backends/:backendId/:action' component={EditBackend} props={props} />

                <RouteWithProps path='/apis/new' component={NewAPI} props={props} />
                <RouteWithProps path='/apis/:apiId' component={Dashboard} props={props} />
                <RouteWithProps exact path='/apis' component={Apis} props={props} />
            </Switch>
        </QueryClientProvider>
    </div >
}

function Subscriptions(props) {
    const history = useHistory()
    const params = useParams()

    const columns = [
        {
            title: 'Name',
            filterId: 'name',
            content: (item) => item.name,
        }
    ];

    useEffect(() => {
        props.setTitle('Subscriptions')

        return () => props.setTitle('')
    }, [])

    const client = nextClient.forEntityNext(nextClient.ENTITIES.API_CONSUMER_SUBSCRIPTIONS)

    const rawSubscriptions = useQuery(["getSubscriptions"], () => {
        return client.findAllWithPagination({
            page: 1,
            pageSize: 15,
            filtered: [{
                id: 'api_ref',
                value: params.apiId
            }]
        })
    })

    const deleteItem = item => client.delete(item.id)
        .then(() => window.location.reload())

    const fields = []

    return <Loader loading={rawSubscriptions.isLoading}>

        <Table
            parentProps={{ params }}
            navigateTo={(item) => history.push(`/apis/${params.apiId}/subscriptions/${item.id}/edit`)}
            navigateOnEdit={(item) => history.push(`/apis/${params.apiId}/subscriptions/${item.id}/edit`)}
            selfUrl="subscriptions"
            defaultTitle="Subscription"
            itemName="Subscription"
            columns={columns}
            fields={fields}
            deleteItem={deleteItem}
            fetchTemplate={client.template}
            fetchItems={() => Promise.resolve(rawSubscriptions.data || [])}
            defaultSort="name"
            defaultSortDesc="true"
            showActions={true}
            showLink={false}
            extractKey={(item) => item.id}
            rowNavigation={true}
            hideAddItemAction={true}
            itemUrl={(i) => `/bo/dashboard/apis/${params.apiId}/subscriptions/${i.id}/edit`}
            rawEditUrl={true}
            displayTrash={(item) => item.id === props.globalEnv.adminApiId}
            injectTopBar={() => (
                <div className="btn-group input-group-btn">
                    <Link className="btn btn-primary btn-sm" to="subscriptions/new">
                        <i className="fas fa-plus-circle" /> Create new subscription
                    </Link>
                    {props.injectTopBar}
                </div>
            )} />
    </Loader>
}

function SubscriptionDesigner(props) {
    const params = useParams()
    const history = useHistory()

    const [subscription, setSubscription] = useState()

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId)
    )

    const rawSubscription = useQuery(["getSubscription", params.subscriptionId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.API_CONSUMER_SUBSCRIPTIONS).findById(params.subscriptionId),
        {
            onSuccess: setSubscription
        }
    )

    // prevent schema to have a empty consumers list
    if (rawAPI.isLoading || !subscription)
        return null

    const schema = {
        location: {
            type: 'location'
        },
        name: {
            type: 'string',
            label: 'Name'
        },
        description: {
            type: 'string',
            label: 'Description'
        },
        enabled: {
            type: 'boolean',
            label: 'Enabled'
        },
        owner_ref: {
            type: 'string',
            label: 'Owner'
        },
        consumer_ref: {
            type: 'select',
            label: 'Consumer',
            props: {
                options: rawAPI.data.consumers,
                optionsTransformer: {
                    value: 'id',
                    label: 'name'
                }
            }
        },
        token_refs: {
            type: 'array',
            label: 'Token refs'
        }
    }

    const flow = [
        'location',
        {
            type: 'group',
            name: 'Informations',
            collapsable: false,
            fields: ['name', 'description', 'enabled'],
        },
        {
            type: 'group',
            name: 'Ownership',
            collapsable: false,
            fields: ['owner_ref', 'consumer_ref', 'token_refs'],
        },
    ]

    const updateSubscription = () => {
        return nextClient
            .forEntityNext(nextClient.ENTITIES.API_CONSUMER_SUBSCRIPTIONS)
            .update(subscription)
            .then(() => history.push(`/apis/${params.apiId}/subscriptions`))
    }

    return <Loader loading={rawAPI.isLoading || rawSubscription.isLoading}>
        <PageTitle title={subscription.name} {...props}>
            <FeedbackButton
                type="success"
                className="d-flex ms-auto"
                onPress={updateSubscription}
                text="Update"
            />
        </PageTitle>
        <div style={{
            maxWidth: 640,
            margin: 'auto'
        }}>
            <NgForm
                value={subscription}
                schema={schema}
                flow={flow}
                onChange={setSubscription} />
        </div>
    </Loader>
}

function NewSubscription(props) {
    const params = useParams()
    const history = useHistory()

    const [subscription, setSubscription] = useState()

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId))

    const templatesQuery = useQuery(["getTemplate"],
        () => nextClient.forEntityNext(nextClient.ENTITIES.API_CONSUMER_SUBSCRIPTIONS).template(),
        {
            enabled: !!rawAPI.data,
            onSuccess: sub => setSubscription({
                ...sub,
                consumer_ref: rawAPI.data.consumers?.length > 0 ? rawAPI.data.consumers[0]?.id : undefined
            })
        }
    )

    // prevent schema to have a empty consumers list
    if (rawAPI.isLoading || !subscription)
        return null

    const schema = {
        location: {
            type: 'location'
        },
        name: {
            type: 'string',
            label: 'Name'
        },
        description: {
            type: 'string',
            label: 'Description'
        },
        enabled: {
            type: 'boolean',
            label: 'Enabled'
        },
        owner_ref: {
            type: 'string',
            label: 'Owner'
        },
        consumer_ref: {
            type: 'select',
            label: 'Consumer',
            props: {
                options: rawAPI.data.consumers,
                optionsTransformer: {
                    value: 'id',
                    label: 'name'
                }
            }
        },
        token_refs: {
            type: 'array',
            label: 'Token refs'
        }
    }

    const flow = [
        'location',
        {
            type: 'group',
            name: 'Informations',
            collapsable: false,
            fields: ['name', 'description', 'enabled'],
        },
        {
            type: 'group',
            name: 'Ownership',
            collapsable: false,
            fields: ['owner_ref', 'consumer_ref', 'token_refs'],
        },
    ]

    const updateSubscription = () => {
        return nextClient
            .forEntityNext(nextClient.ENTITIES.API_CONSUMER_SUBSCRIPTIONS)
            .create({
                ...subscription,
                api_ref: params.apiId
            })
            .then(() => history.push(`/apis/${params.apiId}/subscriptions`))
    }

    return <Loader loading={rawAPI.isLoading || templatesQuery.isLoading}>
        <PageTitle title={subscription.name} {...props}>
            <FeedbackButton
                type="success"
                className="d-flex ms-auto"
                onPress={updateSubscription}
                text="Update"
            />
        </PageTitle>
        <div style={{
            maxWidth: 640,
            margin: 'auto'
        }}>
            <NgForm
                value={subscription}
                schema={schema}
                flow={flow}
                onChange={setSubscription} />
        </div>
    </Loader>
}

function RouteDesigner(props) {
    const params = useParams()
    const history = useHistory()

    const [schema, setSchema] = useState()
    const [route, setRoute] = useState({})

    const [backends, setBackends] = useState([])

    const backendsQuery = useQuery(['getBackends'],
        () => nextClient.forEntityNext(nextClient.ENTITIES.BACKENDS).findAll(),
        {
            enabled: backends.length <= 0,
            onSuccess: setBackends
        })

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId), {
        retry: 0,
        enabled: backendsQuery.data !== undefined,
        onSuccess: data => {
            setRoute(data.routes.find(route => route.id === params.routeId))
            setSchema({
                name: {
                    type: 'string',
                    label: 'Route name',
                    placeholder: 'My users route'
                },
                frontend: {
                    type: 'form',
                    label: 'Frontend',
                    schema: NgFrontend.schema,
                    props: {
                        v2: {
                            folded: ['domains', 'methods'],
                            flow: NgFrontend.flow,
                        }
                    }
                    // flow: NgFrontend.flow,
                },
                flow_ref: {
                    type: 'select',
                    label: 'Flow ID',
                    props: {
                        options: data.flows,
                        optionsTransformer: {
                            label: 'name',
                            value: 'id',
                        }
                    },
                },
                backend: {
                    type: 'select',
                    label: 'Backend',
                    props: {
                        options: [...data.backends, ...backends],
                        optionsTransformer: {
                            value: 'id',
                            label: 'name'
                        }
                    }
                    // return <BackendSelector
                    //     enabled
                    //     backends={[...data.backends, ...backends]}
                    //     setUsingExistingBackend={e => {
                    //         props.rootOnChange({
                    //             ...props.rootValue,
                    //             usingExistingBackend: e
                    //         })
                    //     }}
                    //     onChange={backend_ref => {
                    //         props.rootOnChange({
                    //             ...props.rootValue,
                    //             usingExistingBackend: true,
                    //             backend: backend_ref
                    //         })
                    //     }}
                    //     usingExistingBackend={props.rootValue.usingExistingBackend !== undefined ?
                    //         props.rootValue.usingExistingBackend : (typeof props.rootValue.backend === 'string')
                    //     }
                    //     route={props.rootValue}
                    // />
                    // }
                    // type: 'form',
                    // label: 'Backend',
                    // schema: NgBackend.schema,
                    // flow: NgBackend.flow
                }
            })
        }
    })

    const flow = [
        {
            type: 'group',
            name: 'Domains information',
            collapsable: true,
            fields: ['frontend']
        },
        {
            type: 'group',
            collapsable: true,
            collapsed: true,
            name: 'Selected flow',
            fields: ['flow_ref'],
        },
        {
            type: 'group',
            collapsable: true,
            collapsed: true,
            name: 'Backend configuration',
            fields: ['backend'],
        },
        {
            type: 'group',
            collapsable: true,
            collapsed: true,
            name: 'Additional informations',
            fields: ['name'],
        }
    ]

    const updateRoute = () => {
        return nextClient
            .forEntityNext(nextClient.ENTITIES.APIS)
            .update({
                ...rawAPI.data,
                routes: rawAPI.data.routes.map(item => {
                    if (item.id === route.id)
                        return route
                    return item
                })
            })
            .then(() => history.push(`/apis/${params.apiId}/routes`))
    }

    return <Loader loading={rawAPI.isLoading || !schema}>
        <PageTitle title={route.name || "Update the route"} {...props}>
            <FeedbackButton
                type="success"
                className="d-flex ms-auto"
                onPress={updateRoute}
                disabled={!route.flow_ref}
                text="Update"
            />
        </PageTitle>
        <div style={{
            maxWidth: 640,
            margin: 'auto'
        }}>
            <NgForm
                value={route}
                flow={flow}
                schema={schema}
                onChange={newValue => setRoute(newValue)} />
        </div>
    </Loader>
}

function NewRoute(props) {
    const params = useParams()
    const history = useHistory()

    const [schema, setSchema] = useState()

    const [backends, setBackends] = useState([])

    const backendsQuery = useQuery(['getBackends'],
        () => nextClient.forEntityNext(nextClient.ENTITIES.BACKENDS).findAll(),
        {
            enabled: backends.length <= 0,
            onSuccess: setBackends
        })

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId), {
        retry: 0,
        enabled: backendsQuery.data !== undefined,
        onSuccess: data => {
            setSchema({
                name: {
                    type: 'string',
                    label: 'Route name',
                    placeholder: 'My users route'
                },
                frontend: {
                    type: 'form',
                    label: 'Frontend',
                    schema: NgFrontend.schema,
                    flow: NgFrontend.flow,
                    // v2: {
                    //     folded: ['domains'],
                    //     flow: [
                    //         "domains",
                    //     ],
                    // }
                },
                flow_ref: {
                    type: 'select',
                    label: 'Flow ID',
                    props: {
                        options: data.flows,
                        optionsTransformer: {
                            label: 'name',
                            value: 'id',
                        }
                    },
                },
                backend: {
                    // type: 'form',
                    // label: 'Backend',
                    renderer: props => {
                        return <BackendSelector
                            enabled
                            backends={[...data.backends, ...backends]}
                            setUsingExistingBackend={e => {
                                props.rootOnChange({
                                    ...props.rootValue,
                                    usingExistingBackend: e
                                })
                            }}
                            onChange={backend_ref => {
                                props.rootOnChange({
                                    ...props.rootValue,
                                    usingExistingBackend: true,
                                    backend: backend_ref
                                })
                            }}
                            usingExistingBackend={props.rootValue.usingExistingBackend}
                            route={props.rootValue}
                        />
                    }
                    // schema: NgBackend.schema,
                    // flow: NgBackend.flow
                }
            })
        }
    })

    const flow = [
        {
            type: 'group',
            collapsable: true,
            collapsed: true,
            name: '1. Set your domains',
            fields: ['frontend'],
            summaryFields: ['domains']
        },
        {
            type: 'group',
            collapsable: true,
            collapsed: true,
            name: '2. Add plugins to your route by selecting a flow',
            fields: ['flow_ref'],
        },
        {
            type: 'group',
            collapsable: true,
            collapsed: true,
            name: '3. Configure the backend',
            fields: ['backend'],
        },
        {
            type: 'group',
            collapsable: true,
            collapsed: true,
            name: '4. Additional informations',
            fields: ['name'],
        }
    ]

    const [route, setRoute] = useState({})

    const saveRoute = () => {
        return nextClient
            .forEntityNext(nextClient.ENTITIES.APIS)
            .update({
                ...rawAPI.data,
                routes: [
                    ...rawAPI.data.routes, {
                        ...route,
                        id: v4()
                    }
                ]
            })
            .then(() => history.push(`/apis/${params.apiId}/routes`))
    }

    const templatesQuery = useQuery(["getTemplates"],
        () => Promise.all([
            nextClient.forEntityNext(nextClient.ENTITIES.BACKENDS).template(),
            fetch(`/bo/api/proxy/api/frontends/_template`, {
                method: 'GET',
                credentials: 'include',
                headers: {
                    Accept: 'application/json',
                },
            })
                .then(r => r.json())
        ]), {
        retry: 0,
        onSuccess: ([backendTemplate, frontendTemplate]) => {
            setRoute({
                ...route,
                frontend: frontendTemplate,
                backend: backendTemplate,
                usingExistingBackend: false
            })
        }
    })

    return <Loader loading={rawAPI.isLoading || !schema || templatesQuery.isLoading}>
        <PageTitle title="New Route" {...props} style={{ paddingBottom: 0 }} />

        <div style={{
            maxWidth: 640,
            margin: 'auto'
        }}>
            <NgForm
                value={route}
                flow={flow}
                schema={schema}
                onChange={newValue => setRoute(newValue)} />
            <FeedbackButton
                type="success"
                className="d-flex mt-3 ms-auto"
                onPress={saveRoute}
                disabled={!route.flow_ref}
                text="Create"
            />
        </div>
    </Loader>
}

function Consumers(props) {
    const history = useHistory()
    const params = useParams()

    const columns = [
        {
            title: 'Name',
            filterId: 'name',
            content: (item) => item.name,
        }
    ];

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId), {
        retry: 0
    })

    useEffect(() => {
        props.setTitle(`Consumers of ${rawAPI.data?.name}`)

        return () => props.setTitle('')
    }, [rawAPI.data])

    const client = nextClient.forEntityNext(nextClient.ENTITIES.APIS)
    const api = rawAPI.data;

    const deleteItem = item => client.update({
        ...api,
        consumers: api.consumers.filter(f => f.id !== item.id)
    })
        .then(() => window.location.reload())

    const fields = []

    return <Loader loading={rawAPI.isLoading}>

        <Table
            parentProps={{ params }}
            navigateTo={(item) => history.push(`/apis/${params.apiId}/consumers/${item.id}/edit`)}
            navigateOnEdit={(item) => history.push(`/apis/${params.apiId}/consumers/${item.id}/edit`)}
            selfUrl="consumers"
            defaultTitle="Consumer"
            itemName="Consumer"
            columns={columns}
            fields={fields}
            deleteItem={deleteItem}
            fetchTemplate={() => Promise.resolve({
                id: v4(),
                name: "New consumer",
                consumer_kind: "apikey",
                config: {}
            })}
            fetchItems={() => Promise.resolve(rawAPI.data?.consumers || [])}
            defaultSort="name"
            defaultSortDesc="true"
            showActions={true}
            showLink={false}
            extractKey={(item) => item.id}
            rowNavigation={true}
            hideAddItemAction={true}
            itemUrl={(i) => `/bo/dashboard/apis/${params.apiId}/consumers/${i.id}/edit`}
            rawEditUrl={true}
            displayTrash={(item) => item.id === props.globalEnv.adminApiId}
            injectTopBar={() => (
                <div className="btn-group input-group-btn">
                    <Link className="btn btn-primary btn-sm" to="consumers/new">
                        <i className="fas fa-plus-circle" /> Create new consumer
                    </Link>
                    {props.injectTopBar}
                </div>
            )} />
    </Loader>
}

const TEMPLATES = {
    apikey: {
        throttlingQuota: 1000,
        dailyQuota: 1000,
        monthlyQuota: 1000
    },
    mtls: {},
    keyless: {},
    oauth2: {},
    jwt: {}
}

function NewConsumer(props) {
    const params = useParams()
    const history = useHistory()

    const [consumer, setConsumer] = useState({
        id: v4(),
        name: "New consumer",
        consumer_kind: "apikey",
        settings: TEMPLATES.apikey,
        status: "staging",
        subscriptions: []
    })

    const schema = {
        name: {
            type: 'string',
            label: 'Name'
        },
        consumer_kind: {
            renderer: props => {
                return <div className="row mb-3">
                    <label className="col-xs-12 col-sm-2 col-form-label" style={{ textAlign: 'right' }}>Consumer kind</label>
                    <div className="col-sm-10">
                        <NgSelectRenderer
                            value={props.value}
                            onChange={newType => {
                                props.rootOnChange({
                                    ...props.rootValue,
                                    settings: TEMPLATES[newType],
                                    consumer_kind: newType
                                })
                            }}
                            label="Plan Type"
                            ngOptions={{ spread: true }}
                            margin={0}
                            style={{ flex: 1 }}
                            options={['apikey', 'mtls', 'keyless', 'oauth2', 'jwt']}
                        />
                    </div>
                </div>
            }
        },
        status: {
            type: 'dots',
            label: "Status",
            props: {
                options: ['staging', 'published', 'deprecated', 'closed'],
            },
        },
        description: {
            renderer: ({ rootValue }) => {
                const descriptions = {
                    staging: "This is the initial phase of a plan, where it exists in draft mode. You can configure the plan, but it won’t be visible or accessible to users",
                    published: "When your plan is finalized, you can publish it to allow API consumers to view and subscribe to it via the APIM Portal. Once published, consumers can use the API through the plan. Published plans remain editable",
                    deprecated: "Deprecating a plan makes it unavailable on the APIM Portal, preventing new subscriptions. However, existing subscriptions remain unaffected, ensuring no disruption to current API consumers",
                    closed: "Closing a plan terminates all associated subscriptions, and this action is irreversible. API consumers previously subscribed to the plan will no longer have access to the API"
                };

                return <div className="row mb-3" style={{ marginTop: "-1rem" }}>
                    <label className="col-xs-12 col-sm-2 col-form-label" />
                    <div className="col-sm-10" style={{ fontStyle: 'italic' }}>
                        {descriptions[rootValue?.status]}
                    </div>
                </div>
            }
        },
        auto_validation: {
            type: 'box-bool',
            label: 'Auto-validation',
            props: {
                description: "When creating a customer, you can enable subscription auto-validation to immediately approve subscription requests. If Auto validate subscription is disabled, the API publisher must approve all subscription requests."
            }
        },
        settings: {
            type: 'json',
            label: 'Plan configuration'
        }
    }

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId))

    const savePlan = () => {
        return nextClient
            .forEntityNext(nextClient.ENTITIES.APIS)
            .update({
                ...rawAPI.data,
                consumers: [...rawAPI.data.consumers, consumer]
            })
            .then(() => history.push(`/apis/${params.apiId}`))
    }

    return <Loader loading={rawAPI.isLoading}>

        <PageTitle title="New Plan" {...props} style={{ paddingBottom: 0 }} />

        <div style={{
            maxWidth: 640,
            margin: 'auto'
        }}>
            <NgForm
                value={consumer}
                // flow={flow}
                schema={schema}
                onChange={newValue => setConsumer(newValue)} />
            <Button
                type="success"
                className="btn-sm ms-auto d-flex"
                onClick={savePlan}
                text="Create"
            />
        </div>
    </Loader >
}

function ConsumerDesigner(props) {
    const params = useParams()
    const history = useHistory()

    const [consumer, setConsumer] = useState()

    const schema = {
        name: {
            type: 'string',
            label: 'Name'
        },
        consumer_kind: {
            renderer: props => {
                return <div className="row mb-3">
                    <label className="col-xs-12 col-sm-2 col-form-label" style={{ textAlign: 'right' }}>Consumer kind</label>
                    <div className="col-sm-10">
                        <NgSelectRenderer
                            value={props.value}
                            onChange={newType => {
                                props.rootOnChange({
                                    ...props.rootValue,
                                    settings: TEMPLATES[newType],
                                    consumer_kind: newType
                                })
                            }}
                            label="Plan Type"
                            ngOptions={{ spread: true }}
                            margin={0}
                            style={{ flex: 1 }}
                            options={['apikey', 'mtls', 'keyless', 'oauth2', 'jwt']}
                        />
                    </div>
                </div>
            }
        },
        status: {
            type: 'dots',
            label: "Status",
            props: {
                options: ['staging', 'published', 'deprecated', 'closed'],
            },
        },
        description: {
            renderer: ({ rootValue }) => {
                const descriptions = {
                    staging: "This is the initial phase of a plan, where it exists in draft mode. You can configure the plan, but it won’t be visible or accessible to users",
                    published: "When your plan is finalized, you can publish it to allow API consumers to view and subscribe to it via the APIM Portal. Once published, consumers can use the API through the plan. Published plans remain editable",
                    deprecated: "Deprecating a plan makes it unavailable on the APIM Portal, preventing new subscriptions. However, existing subscriptions remain unaffected, ensuring no disruption to current API consumers",
                    closed: "Closing a plan terminates all associated subscriptions, and this action is irreversible. API consumers previously subscribed to the plan will no longer have access to the API"
                };

                return <div className="row mb-3" style={{ marginTop: "-1rem" }}>
                    <label className="col-xs-12 col-sm-2 col-form-label" />
                    <div className="col-sm-10" style={{ fontStyle: 'italic' }}>
                        {descriptions[rootValue?.status]}
                    </div>
                </div>
            }
        },
        auto_validation: {
            type: 'box-bool',
            label: 'Auto-validation',
            props: {
                description: "When creating a customer, you can enable subscription auto-validation to immediately approve subscription requests. If Auto validate subscription is disabled, the API publisher must approve all subscription requests."
            }
        },
        settings: {
            type: 'json',
            label: 'Plan configuration'
        }
    }

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId), {
        onSuccess: api => {
            setConsumer(api.consumers.find(item => item.id === params.consumerId))
        }
    })

    const updatePlan = () => {
        return nextClient
            .forEntityNext(nextClient.ENTITIES.APIS)
            .update({
                ...rawAPI.data,
                consumers: rawAPI.data.consumers.map(item => {
                    if (item.id === consumer.id)
                        return consumer
                    return item
                })
            })
            .then(() => history.push(`/apis/${params.apiId}`))
    }

    return <Loader loading={rawAPI.isLoading}>

        <PageTitle title={`Update ${consumer?.name}`} {...props} style={{ paddingBottom: 0 }}>
            <FeedbackButton
                type="success"
                className="ms-2 mb-1"
                onPress={updatePlan}
                text="Update"
            />
        </PageTitle>

        <div style={{
            maxWidth: 640,
            margin: 'auto'
        }}>
            <NgForm
                value={consumer}
                // flow={flow}
                schema={schema}
                onChange={newValue => setConsumer(newValue)} />
        </div>
    </Loader>
}


function Routes(props) {
    const history = useHistory()
    const params = useParams()

    const columns = [
        {
            title: 'Name',
            filterId: 'name',
            content: (item) => item.name,
        },
        { title: 'Domains', filterId: 'frontend.domains', content: (item) => item.description },
    ];

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId), {
        retry: 0
    })

    useEffect(() => {
        props.setTitle(`Routes of ${rawAPI.data?.name}`)

        return () => props.setTitle('')
    }, [rawAPI.data])

    const client = nextClient.forEntityNext(nextClient.ENTITIES.APIS)
    const api = rawAPI.data;

    const deleteItem = item => client.update({
        ...api,
        routes: api.routes.filter(f => f.id !== item.id)
    })
        .then(() => window.location.reload())

    const fields = []

    return <Loader loading={rawAPI.isLoading}>

        <Table
            parentProps={{ params }}
            navigateTo={(item) => history.push(`/apis/${params.apiId}/routes/${item.id}/edit`)}
            navigateOnEdit={(item) => history.push(`/apis/${params.apiId}/routes/${item.id}/edit`)}
            selfUrl="routes"
            defaultTitle="Route"
            itemName="Route"
            columns={columns}
            fields={fields}
            deleteItem={deleteItem}
            fetchTemplate={client.template}
            fetchItems={() => Promise.resolve(rawAPI.data?.routes || [])}
            defaultSort="name"
            defaultSortDesc="true"
            showActions={true}
            showLink={false}
            extractKey={(item) => item.id}
            rowNavigation={true}
            hideAddItemAction={true}
            itemUrl={(i) => `/bo/dashboard/apis/${params.apiId}/routes/${i.id}/edit`}
            rawEditUrl={true}
            displayTrash={(item) => item.id === props.globalEnv.adminApiId}
            injectTopBar={() => (
                <div className="btn-group input-group-btn">
                    <Link className="btn btn-primary btn-sm" to="routes/new">
                        <i className="fas fa-plus-circle" /> Create new route
                    </Link>
                    {props.injectTopBar}
                </div>
            )} />
    </Loader>
}

function Backends(props) {
    const history = useHistory()
    const params = useParams()

    const columns = [
        {
            title: 'Name',
            filterId: 'name',
            content: (item) => item.name,
        },
        { title: 'Description', filterId: 'description', content: (item) => item.description },
    ];

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId), {
        retry: 0
    })

    useEffect(() => {
        props.setTitle(`Backends of ${rawAPI.data?.name}`)

        return () => props.setTitle('')
    }, [rawAPI.data])

    const client = nextClient.forEntityNext(nextClient.ENTITIES.BACKENDS)
    const api = rawAPI.data;

    const deleteItem = item => client.update({
        ...api,
        backends: api.backends.filter(f => f.id !== item.id)
    })

    // const updateItem = item => client.update({
    //     ...api,
    //     backends: api.backends.map(backend => {
    //         if (backend.id === item.id)
    //             return item

    //         return backend
    //     })
    // })

    const fields = []

    return <Loader loading={rawAPI.isLoading}>

        <Table
            parentProps={{ params }}
            navigateTo={(item) => history.push(`/apis/${params.apiId}/backends/${item.id}/edit`)}
            navigateOnEdit={(item) => history.push(`/apis/${params.apiId}/backends/${item.id}/edit`)}
            selfUrl="backends"
            defaultTitle="Backend"
            itemName="Backend"
            columns={columns}
            fields={fields}
            deleteItem={deleteItem}
            fetchTemplate={client.template}
            fetchItems={() => Promise.resolve(rawAPI.data?.backends || [])}
            defaultSort="name"
            defaultSortDesc="true"
            showActions={true}
            showLink={false}
            extractKey={(item) => item.id}
            rowNavigation={true}
            hideAddItemAction={true}
            itemUrl={(i) => `/bo/dashboard/apis/${params.apiId}/backends/${i.id}/edit`}
            rawEditUrl={true}
            displayTrash={(item) => item.id === props.globalEnv.adminApiId}
            injectTopBar={() => (
                <div className="btn-group input-group-btn">
                    <Link className="btn btn-primary btn-sm" to="backends/new">
                        <i className="fas fa-plus-circle" /> Create new backend
                    </Link>
                    {props.injectTopBar}
                </div>
            )} />
    </Loader>
}

function NewBackend(props) {
    const params = useParams()
    const history = useHistory()

    const [backend, setBackend] = useState()

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId))

    const saveBackend = () => {
        return nextClient
            .forEntityNext(nextClient.ENTITIES.APIS)
            .update({
                ...rawAPI.data,
                backends: [...rawAPI.data.backends, backend]
            })
            .then(() => history.push(`/apis/${params.apiId}/backends`))
    }

    const templateQuery = useQuery(["getTemplate"],
        nextClient.forEntityNext(nextClient.ENTITIES.BACKENDS).template, {
        retry: 0,
        onSuccess: (data) => setBackend({
            id: v4(),
            name: 'My new backend',
            ...data.backend
        })
    });

    return <Loader loading={templateQuery.isLoading || rawAPI.isLoading}>

        <PageTitle title="New Backend" {...props} style={{ paddingBottom: 0 }}>
            <FeedbackButton
                type="success"
                className="ms-2 mb-1"
                onPress={saveBackend}
                text="Create"
            />
        </PageTitle>

        <div style={{
            maxWidth: 640,
            margin: 'auto'
        }}>
            <BackendForm
                state={{
                    form: {
                        schema: {
                            name: {
                                label: 'Name',
                                type: 'string',
                                placeholder: 'New backend'
                            },
                            backend: {
                                type: 'form',
                                schema: NgBackend.schema,
                                flow: NgBackend.flow
                            }
                        },
                        flow: ['name', 'backend'],
                        value: backend
                    }
                }}
                onChange={setBackend} />
        </div>
    </Loader>
}

function EditBackend(props) {
    const params = useParams()
    const history = useHistory()

    const [backend, setBackend] = useState()

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId), {
        onSuccess: data => {
            setBackend(data.backends.find(item => item.id === params.backendId))
        }
    })

    const updateBackend = () => {
        return nextClient
            .forEntityNext(nextClient.ENTITIES.APIS)
            .update({
                ...rawAPI.data,
                backends: rawAPI.data.backends.map(item => {
                    if (item.id === backend.id)
                        return backend
                    return item
                })
            })
            .then(() => history.push(`/apis/${params.apiId}/backends`))
    }

    return <Loader loading={rawAPI.isLoading}>
        <PageTitle title="Update Backend" {...props} style={{ paddingBottom: 0 }}>
            <FeedbackButton
                type="success"
                className="ms-2 mb-1"
                onPress={updateBackend}
                text="Update"
            />
        </PageTitle>

        <div style={{
            maxWidth: 640,
            margin: 'auto'
        }}>
            <BackendForm
                state={{
                    form: {
                        schema: {
                            name: {
                                label: 'Name',
                                type: 'string',
                                placeholder: 'New backend'
                            },
                            backend: {
                                type: 'form',
                                schema: NgBackend.schema,
                                flow: NgBackend.flow
                            }
                        },
                        flow: ['name', 'backend'],
                        value: backend
                    }
                }}
                onChange={setBackend} />
        </div>
    </Loader>
}

function SidebarComponent(props) {
    const params = useParams()
    useEffect(() => {
        props.setSidebarContent(<Sidebar params={params} />);
        return () => props.setSidebarContent(null)
    }, [params])

    return null
}

function NewFlow(props) {
    const history = useHistory()
    const params = useParams()

    useEffect(() => {
        props.setTitle("Create a new Flow")
    }, [])

    const [flow, setFlow] = useState({
        id: v4(),
        name: 'New flow name',
        plugins: []
    })

    const schema = {
        name: {
            type: 'string',
            props: { label: 'Name' },
        }
    }

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId), {
        retry: 0
    })

    const createFlow = () => {
        nextClient.forEntityNext(nextClient.ENTITIES.APIS)
            .update({
                ...rawAPI.data,
                flows: [...rawAPI.data.flows, flow]
            })
            .then(() => history.push(`/apis/${params.apiId}/flows/${flow.id}`));
    }

    return <Loader loading={rawAPI.isLoading}>
        <Form
            schema={schema}
            flow={["name"]}
            value={flow}
            onChange={setFlow}
        />
        <Button
            type="success"
            className="btn-sm ms-auto d-flex"
            onClick={createFlow}
            text="Create"
        />
    </Loader>
}

function NewAPI(props) {
    const history = useHistory()

    useEffect(() => {
        props.setTitle("Create a new API")
    }, [])

    const [value, setValue] = useState({})

    const template = useQuery(["getTemplate"],
        nextClient.forEntityNext(nextClient.ENTITIES.APIS).template, {
        retry: 0,
        onSuccess: (data) => {
            setValue(data)
        }
    });

    // version: String,
    // state: ApiState,
    // blueprint: ApiBlueprint,
    // routes: Seq[ApiRoute],
    // backends: Seq[NgBackend],
    // flows: Seq[ApiFlows],
    // clients: Seq[ApiBackendClient],
    // documentation: Option[ApiDocumentation],
    // consumers: Seq[ApiConsumer],
    // deployments: Seq[ApiDeployment]

    const schema = {
        location: {
            type: 'location',
            props: {},
        },
        id: { type: 'string', disabled: true, props: { label: 'id', placeholder: '---' } },
        name: {
            type: 'string',
            props: { label: 'Name' },
        },
        description: {
            type: 'string',
            props: { label: 'Description' },
        },
        metadata: {
            type: 'object',
            props: { label: 'metadata' },
        },
        tags: {
            type: 'array',
            props: { label: 'tags' },
        },
        debug_flow: {
            type: 'bool',
            props: { label: 'Debug' },
        },
        export_reporting: {
            type: 'bool',
            props: { label: 'Export reports' },
        },
        capture: {
            type: 'bool',
            props: { label: 'Capture traffic' },
        }
    }
    const editionFlow = ['location', 'id', 'name', 'description', 'metadata', 'tags', 'debug_flow', 'export_reporting', 'capture']
    const flow = ['location', 'name', 'description']

    const createApi = () => {
        nextClient.forEntityNext(nextClient.ENTITIES.APIS)
            .create(value)
            .then(() => history.push(`/apis/${value.id}`));
    }

    return <Loader loading={template.isLoading}>
        <Form
            schema={schema}
            flow={flow}
            value={value}
            onChange={setValue}
        />
        <Button
            type="success"
            className="btn-sm ms-auto d-flex"
            onClick={createApi}
            text="Create"
        />
    </Loader>
}

function Apis(props) {
    const ref = useRef()
    const params = useParams()
    const history = useHistory()

    useEffect(() => {
        props.setTitle("Apis")
    }, [])

    const [fields, setFields] = useState({
        id: false,
        name: true,
    })
    const columns = [
        {
            title: 'Id',
            content: item => item.id
        },
        {
            title: 'Name',
            content: item => item.name
        }
    ];

    const fetchItems = (paginationState) => nextClient
        .forEntityNext(nextClient.ENTITIES.APIS)
        .findAllWithPagination(paginationState)

    const fetchTemplate = () => nextClient
        .forEntityNext(nextClient.ENTITIES.APIS)
        .template()

    return <>

        <Table
            ref={ref}
            parentProps={{ params }}
            navigateTo={(item) => history.push(`/apis/${item.id}`)}
            navigateOnEdit={(item) => history.push(`/apis/${item.id}`)}
            selfUrl="apis"
            defaultTitle="Api"
            itemName="Api"
            formSchema={null}
            formFlow={null}
            columns={columns}
            fields={fields}
            deleteItem={(item) => nextClient
                .forEntityNext(nextClient.ENTITIES.APIS).deleteById(item.id)
                .then(() => window.location.reload())
            }
            defaultSort="name"
            defaultSortDesc="true"
            fetchItems={fetchItems}
            fetchTemplate={fetchTemplate}
            showActions={true}
            showLink={false}
            extractKey={(item) => item.id}
            rowNavigation={true}
            hideAddItemAction={true}
            itemUrl={(i) => `/bo/dashboard/apis/${i.id}`}
            rawEditUrl={true}
            displayTrash={(item) => item.id === props.globalEnv.adminApiId}
            injectTopBar={() => (
                <div className="btn-group input-group-btn">
                    <Link className="btn btn-primary btn-sm" to="apis/new">
                        <i className="fas fa-plus-circle" /> Create new API
                    </Link>
                    {props.injectTopBar}
                </div>
            )} />
    </>
}

function FlowDesigner(props) {
    const history = useHistory()
    const params = useParams()

    const isCreation = params.action === 'new';

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId),
        {
            retry: 0
        })

    const [flow, setFlow] = useState()
    const ref = useRef(flow)

    useEffect(() => {
        ref.current = flow;
    }, [flow])

    useEffect(() => {
        if (rawAPI.data) {
            setFlow(rawAPI.data.flows.find(flow => flow.id === params.flowId))

            dynamicTitleContent.value = (
                <PageTitle
                    style={{
                        paddingBottom: 0,
                    }}
                    title={rawAPI.data.flows.find(flow => flow.id === params.flowId)?.name}
                    {...props}
                >
                    <FeedbackButton
                        type="success"
                        className="ms-2 mb-1"
                        onPress={saveFlow}
                        text={isCreation ? 'Create a new flow' : 'Save'}
                    />
                </PageTitle>
            );
        }
    }, [rawAPI.data])

    const saveFlow = () => {
        const api = rawAPI.data
        const {
            id, name, plugins
        } = ref.current.value

        return nextClient.forEntityNext(nextClient.ENTITIES.APIS)
            .update({
                ...api,
                flows: api.flows.map(item => {
                    if (item.id === id)
                        return {
                            id, name, plugins
                        }
                    return item
                })
            })
            .then(() => history.replace(`/apis/${params.apiId}/flows`))
    }

    return <Loader loading={rawAPI.isLoading}>

        <div className='designer'>
            <Designer
                history={history}
                value={flow}
                setValue={value => setFlow({ value })}
                setSaveButton={() => { }}
            // setMenu={(n) => this.setState({ menu: n, menuRefreshed: Date.now() })}
            />
        </div>
    </Loader>
}

function Flows(props) {
    const ref = useRef()
    const params = useParams()
    const history = useHistory()

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId),
        {
            retry: 0
        })

    const [fields, setFields] = useState({
        id: false,
        name: true,
    })
    const columns = [
        {
            title: 'Name',
            content: item => item.name
        }
    ];

    useEffect(() => {
        props.setTitle(`Flows of ${rawAPI.data?.name}`)
    }, [rawAPI.data])

    const fetchItems = (paginationState) => Promise.resolve(rawAPI.data.flows)

    const fetchTemplate = () => Promise.resolve({
        id: uuid(),
        name: 'My new flow',
        plugins: []
    })

    return <Loader loading={rawAPI.isLoading}>

        <Table
            ref={ref}
            parentProps={{ params }}
            navigateTo={(item) => history.push(`/apis/${params.apiId}/flows/${item.id}/edit`)}
            navigateOnEdit={(item) => history.push(`/apis/${params.apiId}/flows/${item.id}/edit`)}
            selfUrl="flows"
            defaultTitle="Flow"
            itemName="Flow"
            formSchema={null}
            formFlow={null}
            columns={columns}
            fields={fields}
            // coreFields={['id', 'name']}
            // addField={(fieldPath) => {
            //     const newFields = {
            //         ...fields,
            //         [fieldPath]: true,
            //     };
            //     setFields(newFields);
            //     onFieldsChange(newFields);
            // }}
            // removeField={(fieldPath) => {
            //     const { [fieldPath]: _, ...newFields } = fields;

            //     setFields(newFields);
            //     onFieldsChange(newFields);
            // }}
            // onToggleField={(column, enabled) => {
            //     const newFields = {
            //         ...fields,
            //         [column]: enabled,
            //     };
            //     onFieldsChange(newFields);
            //     setFields(newFields);
            // }}
            deleteItem={(item) => console.log('delete item', item)}
            defaultSort="name"
            defaultSortDesc="true"
            fetchItems={fetchItems}
            fetchTemplate={fetchTemplate}
            showActions={true}
            showLink={false}
            extractKey={(item) => item.id}
            rowNavigation={true}
            hideAddItemAction={true}
            itemUrl={(i) => `/bo/dashboard/apis/${params.apiId}/flows/${i.id}`}
            rawEditUrl={true}
            displayTrash={(item) => item.id === props.globalEnv.adminApiId}
            injectTopBar={() => (
                <div className="btn-group input-group-btn">
                    <Link className="btn btn-primary btn-sm" to="flows/new">
                        <i className="fas fa-plus-circle" /> Create new Flow
                    </Link>
                    {props.injectTopBar}
                </div>
            )}
        />
    </Loader>
}

function Dashboard(props) {
    const params = useParams()
    const history = useHistory()

    useEffect(() => {
        props.setTitle("Dashboard")

        return () => props.setTitle(undefined)
    }, [])

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId),
        {
            retry: 0
        })

    const api = rawAPI.data

    const hasCreateFlow = api && api.flows.length > 0
    const hasCreateRoute = api && api.routes.length > 0
    const hasCreateConsumer = api && api.consumers.length > 0
    const showGettingStarted = !hasCreateFlow || !hasCreateConsumer || !hasCreateRoute

    return <div className='d-flex flex-column gap-3' style={{ maxWidth: 1280 }}>
        <Loader loading={rawAPI.isLoading}>

            {api && <div className='d-flex gap-3'>
                <div className='d-flex flex-column flex-grow gap-3' style={{ maxWidth: 640 }}>
                    {showGettingStarted && <ContainerBlock full>
                        <SectionHeader text="Getting Started" />

                        {hasCreateFlow && hasCreateRoute && !hasCreateConsumer && <Card
                            to={`/apis/${params.apiId}/consumers/new`}
                            title="Create your first API consumer"
                            description={<>
                                <HighlighedText text="API consumer" link={`/apis/${params.apiId}/consumers`} /> allows users or machines to subscribe to your API
                            </>}
                            button={<FeedbackButton type="primaryColor"
                                className="ms-auto d-flex"
                                onPress={() => { }}
                                text="Create" />}
                        />}

                        {hasCreateFlow && !hasCreateRoute && <Card
                            to={`/apis/${params.apiId}/routes/new`}
                            title="Create your first route"
                            description={<>
                                Compose your API with your first <HighlighedText text="Route" link={`/apis/${params.apiId}/routes`} />
                            </>}
                            button={<FeedbackButton type="primaryColor"
                                className="ms-auto d-flex"
                                onPress={() => { }}
                                text="Create" />}
                        />}

                        {!hasCreateFlow && <Card
                            to={`/apis/${params.apiId}/flows/new`}
                            title="Create your first flow of plugins"
                            description={<>
                                Create flows of plufins to apply rules, transformations, and restrictions on routes, enabling advanced traffic control and customization.
                            </>}
                            button={<FeedbackButton type="primaryColor"
                                className="ms-auto d-flex"
                                onPress={() => { }}
                                text="Create" />}
                        />}
                    </ContainerBlock>}
                    <ContainerBlock full highlighted>
                        <APIHeader api={api} />
                        <ApiStats url={`/bo/api/proxy/apis/api.otoroshi.io/v1/apis/${api.id}/live?every=2000`} />

                        <Uptime
                            health={api.health?.today}
                            stopTheCountUnknownStatus={false}
                        />
                        <Uptime
                            health={api.health?.yesterday}
                            stopTheCountUnknownStatus={false}
                        />
                        <Uptime
                            health={api.health?.nMinus2}
                            stopTheCountUnknownStatus={false}
                        />
                    </ContainerBlock>
                    {hasCreateConsumer && <ContainerBlock full>
                        <SectionHeader
                            text="Subscriptions"
                            description={api.consumers.flatMap(c => c.subscriptions).length <= 0 ? 'Souscriptions will appear here' : ''}
                            actions={<Button
                                type="primaryColor"
                                text="Subscribe"
                                className='btn-sm'
                                onClick={() => history.push(`/apis/${params.apiId}/subscriptions/new`)} />} />

                        <SubscriptionsView api={api} />
                    </ContainerBlock>}

                    {hasCreateConsumer && <ContainerBlock full>
                        <SectionHeader text="API Consumers"
                            description={api.consumers.length <= 0 ? 'API consumers will appear here' : ''}
                            actions={<Button
                                type="primaryColor"
                                text="New Consumer"
                                className='btn-sm'
                                onClick={() => history.push(`/apis/${params.apiId}/consumers/new`)} />} />

                        <ApiConsumersView api={api} />
                    </ContainerBlock>}
                </div>
                {api.flows.length > 0 && api.routes.length > 0 && <ContainerBlock>
                    <SectionHeader text="Build your API" description="Manage entities for this API" />
                    <Entities>
                        <FlowsCard flows={api.flows} />
                        <BackendsCard backends={api.backends} />
                        <RoutesCard routes={api.routes} />
                    </Entities>
                </ContainerBlock>}
            </div>}
        </Loader>
    </div>
}

function ApiConsumersView({ api }) {
    return <div>
        <div className='short-table-row'>
            <div>Name</div>
            <div>Description</div>
            <div>Status</div>
            <div>Kind</div>
        </div>
        {api.consumers.map(consumer => {
            return <Consumer key={consumer.id} consumer={consumer} />
        })}
    </div>
}

function Consumer({ consumer }) {
    const history = useHistory()
    const params = useParams()
    const [open, setOpen] = useState(false)

    const CONSUMER_STATUS_COLORS = {
        staging: 'info',
        published: 'success',
        deprecated: 'warning',
        closed: 'danger',
    }

    return <div className='short-table-row'
        style={{
            backgroundColor: 'hsla(184, 9%, 62%, 0.18)',
            borderColor: 'hsla(184, 9%, 62%, 0.4)',
            borderRadius: '.5rem',
            gridTemplateColumns: open ? '1fr' : 'repeat(3, 1fr) 54px 32px'
        }}
        onClick={() => setOpen(!open)}>
        {open && <div style={{ position: 'relative' }}>
            <Button type="primaryColor" className="btn-sm" text="Edit"
                onClick={e => {
                    e.stopPropagation()
                    history.push(`/apis/${params.apiId}/consumers/${consumer.id}/edit`)
                }} style={{
                    position: 'absolute',
                    top: '.5rem',
                    right: 0
                }} />
            <NgCodeRenderer
                raw
                readOnly
                label={undefined}
                value={JSON.stringify(consumer, null, 2)} />
        </div>}
        {!open && <>
            <div>{consumer.name}</div>
            <div>{consumer.description}</div>
            <div className={`badge bg-${CONSUMER_STATUS_COLORS[consumer.status]}`} style={{
                width: 'fit-content',
                border: 'none'
            }}>{consumer.status}</div>
            <div className="badge bg-success" style={{
                border: 'none'
            }}>{consumer.consumer_kind}</div>
            <i className={`fas fa-chevron-${open ? 'down' : 'right'} fa-lg short-table-navigate-icon`} />
        </>}
    </div>
}

function SubscriptionsView({ api }) {
    const [subscriptions, setSubscriptions] = useState([])

    useEffect(() => {
        nextClient
            .forEntityNext(nextClient.ENTITIES.API_CONSUMER_SUBSCRIPTIONS)
            .findAllWithPagination({
                page: 1,
                pageSize: 5,
                filtered: [{
                    id: 'api_ref',
                    value: api.id
                }],
                sorted: [{
                    id: 'dates.created_at',
                    desc: false
                }]
            })
            .then(raw => setSubscriptions(raw.data))
    }, [])
    return <div>
        <div className='short-table-row'>
            <div>Name</div>
            <div>Description</div>
            <div>Created At</div>
            <div>Kind</div>
        </div>
        {subscriptions.map(subscription => {
            return <Subscription subscription={subscription} key={subscription.id} />
        })}
    </div>
}

function Subscription({ subscription }) {
    const params = useParams()
    const history = useHistory()
    const [open, setOpen] = useState(false)

    return <div key={subscription.id}
        className='short-table-row'
        style={{
            backgroundColor: 'hsla(184, 9%, 62%, 0.18)',
            borderColor: 'hsla(184, 9%, 62%, 0.4)',
            borderRadius: '.5rem',
            gridTemplateColumns: open ? '1fr' : 'repeat(3, 1fr) 54px 32px',
            position: 'relative'
        }}
        onClick={() => setOpen(!open)}>
        {open && <>
            <Button type="primaryColor" className="btn-sm" text="Edit"
                onClick={e => {
                    e.stopPropagation()
                    history.push(`/apis/${params.apiId}/subscriptions/${subscription.id}/edit`)
                }} style={{
                    position: 'absolute',
                    top: '1rem',
                    right: '1rem'
                }} />
            <NgCodeRenderer
                readOnly
                style={{
                    overflowX: 'hidden'
                }}
                label="Configuration"
                value={JSON.stringify(subscription, null, 2)} />
        </>}
        {!open && <>
            <div>{subscription.name}</div>
            <div>{subscription.description}</div>
            <div>{moment(new Date(subscription.dates.created_at)).format('DD/MM/YY hh:mm')}</div>
            <div className='badge bg-success' style={{ border: 'none' }}>{subscription.subscription_kind}</div>
            <i className={`fas fa-chevron-${open ? 'down' : 'right'} fa-lg short-table-navigate-icon`} />
        </>}
    </div>
}

function ContainerBlock({ children, full, highlighted }) {
    return <div className={`container ${full ? 'container--full' : ''} ${highlighted ? 'container--highlighted' : ''}`}
        style={{
            margin: 0,
            position: 'relative',
            height: 'fit-content'
        }}>
        {children}
    </div>
}

function APIHeader({ api }) {
    const updateAPI = newAPI => {
        return nextClient
            .forEntityNext(nextClient.ENTITIES.APIS)
            .update(newAPI)
    }

    return <>
        <div className='d-flex align-items-center gap-3'>
            <h2 className='m-0'>{api.name}</h2>
            <APIState value={api.state} />
            {api.state === API_STATE.STAGING && <Button
                type='primaryColor'
                onClick={() => {
                    updateAPI({
                        ...api,
                        state: API_STATE.PUBLISHED
                    })
                        .then(() => window.location.reload())
                }}
                className='btn-sm ms-auto'
                text="Start you API" />}
            {(api.state === API_STATE.PUBLISHED || api.state === API_STATE.DEPRECATED) &&
                <Button
                    type='quiet'
                    onClick={() => {
                        updateAPI({
                            ...api,
                            state: api.state === API_STATE.PUBLISHED ? API_STATE.DEPRECATED : API_STATE.PUBLISHED
                        })
                            .then(() => window.location.reload())
                    }}
                    className='btn-sm ms-auto'
                    text={api.state === API_STATE.PUBLISHED ? "Deprecate your API" : "Publish your API"} />}
            {/* {(api.state === API_STATE.PUBLISHED || api.state === API_STATE.DEPRECATED) &&
                <Button
                    type='danger'
                    onClick={() => {
                        updateAPI({
                            ...api,
                            state: API_STATE.DEPRECATED
                        })
                            .then(() => window.location.reload())
                    }}
                    className='btn-sm ms-auto'
                    text="Close your API" />} */}
        </div>
        <div className='d-flex align-items-center gap-1 mb-3'>
            <p className='m-0 me-2'>{api.description}</p>
            {api.tags.map(tag => <span className='tag' key={tag}>
                {tag}
            </span>)}
        </div>
    </>
}

function APIState({ value }) {
    if (value === API_STATE.STAGING)
        return <span className='badge api-status-started'>
            <i className='fas fa-rocket me-2' />
            Staging
        </span>

    if (value === API_STATE.DEPRECATED)
        return <span className='badge api-status-deprecated'>
            <i className='fas fa-warning me-2' />
            Deprecated
        </span>

    if (value === API_STATE.PUBLISHED)
        return <span className='badge api-status-published'>
            <i className='fas fa-check fa-xs me-2' />
            Published
        </span>


    // TODO  - manage API_STATE.REMOVED
    return null
}

function SectionHeader({ text, description, main, actions }) {
    return <div>
        <div className='d-flex align-items-center justify-content-between'>
            {main ? <h1 className='m-0'>{text}</h1> :
                <h3 className='m-0'>{text}</h3>}
            {actions}
        </div>
        <p>{description}</p>
    </div>
}

function Entities({ children }) {
    return <div className='d-flex flex-column gap-3'>
        {children}
    </div>
}

function Card({ title, description, to, button }) {
    return <Link to={to} className="cards apis-cards cards--large mb-3">
        <div className="cards-body">
            <div className='cards-title d-flex align-items-center justify-content-between'>
                {title}
            </div>
            <p className="cards-description" style={{ position: 'relative' }}>
                {description}
                {button ? button : <i className='fas fa-chevron-right fa-lg navigate-icon' />}
            </p>
        </div>
    </Link>
}

function BackendsCard({ backends }) {
    const params = useParams()

    return <Link to={`/apis/${params.apiId}/backends`} className="cards apis-cards">
        {/* <div
            className="cards-header"
            style={{
                background: `url(/assets/images/svgs/backend.svg)`,
            }}
        ></div> */}
        <div className="cards-body">
            <div className='cards-title d-flex align-items-center justify-content-between'>
                Backends <span className='badge api-status-deprecated'>
                    <i className='fas fa-microchip me-2' />
                    {backends.length}
                </span>
            </div>
            <p className="cards-description" style={{ position: 'relative' }}>
                Design robust, scalable <HighlighedBackendText plural /> with optimized performance, security, and seamless front-end integration.
                <i className='fas fa-chevron-right fa-lg navigate-icon' />
            </p>
        </div>
    </Link>
}

function RoutesCard({ routes }) {
    const params = useParams()
    return <Link to={`/apis/${params.apiId}/routes`} className="cards apis-cards">
        {/* <div
            className="cards-header"
            style={{
                background: `url(/assets/images/svgs/routes.svg)`,
            }}
        ></div> */}
        <div className="cards-body">
            <div className='cards-title d-flex align-items-center justify-content-between'>
                Routes <span className='badge api-status-deprecated'>
                    <i className='fas fa-road me-2' />
                    {routes.length}
                </span>
            </div>
            <p className="cards-description relative">
                Define your <HighlighedRouteText />: connect <HighlighedFrontendText plural /> to <HighlighedBackendText plural /> and customize behavior with <HighlighedFlowsText plural /> like authentication, rate limiting, and transformations.
                <i className='fas fa-chevron-right fa-lg navigate-icon' />
            </p>
        </div>
    </Link>
}

function FlowsCard({ flows }) {
    const params = useParams()
    return <Link to={`/apis/${params.apiId}/flows`} className="cards apis-cards">
        {/* <div
            className="cards-header"
            style={{
                background: `url(/assets/images/svgs/plugins.svg)`,
            }}
        ></div> */}
        <div className="cards-body">
            <div className='cards-title d-flex align-items-center justify-content-between'>
                Flows <span className='badge api-status-deprecated'>
                    <i className='fas fa-road me-2' />
                    {flows.length}
                </span>
            </div>
            <p className="cards-description relative">
                Create flows of <HighlighedPluginsText plural /> to apply rules, transformations, and restrictions on <HighlighedRouteText plural />, enabling advanced traffic control and customization.
                <i className='fas fa-chevron-right fa-lg navigate-icon' />
            </p>
        </div>
    </Link>
}

function HighlighedPluginsText({ plural }) {
    const params = useParams()
    return <HighlighedText text={plural ? 'plugins' : "plugin"} link={`/apis/${params.apiId}/flows`} />
}

function HighlighedBackendText({ plural }) {
    const params = useParams()
    return <HighlighedText text={plural ? 'backends' : "backend"} link={`/apis/${params.apiId}/backends`} />
}

function HighlighedFrontendText({ plural }) {
    const params = useParams()
    return <HighlighedText text={plural ? 'frontends' : "frontend"} link={`/apis/${params.apiId}/frontends`} />
}

function HighlighedRouteText({ plural }) {
    const params = useParams()
    return <HighlighedText text={plural ? 'routes' : "route"} link={`/apis/${params.apiId}/routes`} />
}

function HighlighedFlowsText({ plural }) {
    const params = useParams()
    return <HighlighedText text={plural ? 'flows' : "flow"} link={`/apis/${params.apiId}/flows`} />
}

function HighlighedText({ text, link }) {
    return <Link to={link} className="highlighted-text">{text}</Link>
}