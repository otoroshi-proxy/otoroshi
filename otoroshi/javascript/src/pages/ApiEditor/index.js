import React, { useEffect, useLayoutEffect, useRef, useState } from 'react'

import './index.scss'

import { API_STATE } from './model';
import Sidebar from './Sidebar';
import { Link, Switch, Route, useParams, useHistory, useLocation } from 'react-router-dom';
import { Uptime } from '../../components/Status';
import { Form, Table } from '../../components/inputs';
import { v4 as uuid, v4 } from 'uuid';
import Designer from '../RouteDesigner/Designer';
import SimpleLoader from './SimpleLoader';
import { dynamicTitleContent } from '../../components/DynamicTitleSignal';
import PageTitle from '../../components/PageTitle';
import { FeedbackButton } from '../RouteDesigner/FeedbackButton';
import { fetchWrapperNext, nextClient } from '../../services/BackOfficeServices';
import { QueryClient, QueryClientProvider, useQuery } from 'react-query';
import { Button } from '../../components/Button';
import NgBackend from '../../forms/ng_plugins/NgBackend';
import { NgDotsRenderer, NgForm, NgSelectRenderer } from '../../components/nginputs';
import { BackendForm } from '../RouteDesigner/BackendNode';
import NgFrontend from '../../forms/ng_plugins/NgFrontend';

import moment from 'moment';
import semver from 'semver'

import { ApiStats } from './ApiStats';
import { PublisDraftModalContent } from '../../components/Drafts/DraftEditor';
import { mergeData } from '../../components/Drafts/Compare/utils';
import { useSignalValue } from 'signals-react-safe';
import { signalVersion } from './VersionSignal';
import JwtVerificationOnly from '../../forms/ng_plugins/JwtVerificationOnly';
import { JsonObjectAsCodeInput } from '../../components/inputs/CodeInput';
import NgClientCredentialTokenEndpoint from '../../forms/ng_plugins/NgClientCredentialTokenEndpoint';
import NgHasClientCertMatchingValidator from '../../forms/ng_plugins/NgHasClientCertMatchingValidator';

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

                <RouteWithProps exact path='/apis/:apiId/deployments' component={Deployments} props={props} />
                <RouteWithProps exact path='/apis/:apiId/testing' component={Testing} props={props} />

                <RouteWithProps path='/apis/new' component={NewAPI} props={props} />
                <RouteWithProps path='/apis/:apiId/informations' component={Informations} props={props} />
                <RouteWithProps path='/apis/:apiId' component={Dashboard} props={props} />
                <RouteWithProps exact path='/apis' component={Apis} props={props} />
            </Switch>
        </QueryClientProvider>
    </div>
}

function useDraftOfAPI() {
    const params = useParams()
    const version = useSignalValue(signalVersion)

    const [draft, setDraft] = useState()
    const [api, setAPI] = useState()

    const [draftWrapper, setDraftWrapper] = useState()

    const draftClient = nextClient
        .forEntityNext(nextClient.ENTITIES.DRAFTS);

    const isPublished = !version || version === 'Published'

    const rawAPI = useQuery(["getAPI", params.apiId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.APIS).findById(params.apiId), {
        enabled: !api,
        onSuccess: setAPI
    })

    const query = useQuery(['findDraftById', params.apiId, version], () => nextClient
        .forEntityNext(nextClient.ENTITIES.DRAFTS)
        .findById(params.apiId),
        {
            retry: 0,
            enabled: !draft,
            onSuccess: data => {
                if (data.error) {
                    Promise.all([
                        nextClient
                            .forEntityNext(nextClient.ENTITIES.APIS)
                            .findById(params.apiId),
                        draftClient.template()
                    ])
                        .then(([api, template]) => {
                            const newDraft = {
                                ...template,
                                kind: api.id.split('_')[1],
                                id: api.id,
                                name: api.name,
                                content: api,
                            }
                            draftClient.create(newDraft)
                            setDraftWrapper(newDraft)
                            setDraft(api)
                        })
                } else {
                    setDraftWrapper(data)
                    setDraft(data.content)
                }
            }
        })

    const updateDraft = (optDraft) => {
        return nextClient.forEntityNext(nextClient.ENTITIES.DRAFTS)
            .update({
                ...draftWrapper,
                content: optDraft ? optDraft : draft
            })
            .then(() => setDraft(optDraft ? optDraft : draft))
    }

    const updateAPI = (optAPI) => {
        return nextClient.forEntityNext(nextClient.ENTITIES.APIS)
            .update(optAPI ? optAPI : api)
            .then(() => setAPI(optAPI ? optAPI : api))
    }

    return {
        api,
        item: isPublished ? api : draft,
        draft,
        draftWrapper,
        version,
        tag: version === 'Published' ? 'PROD' : 'DEV',
        setItem: isPublished ? setAPI : setDraft,
        updateItem: isPublished ? updateAPI : updateDraft,
        isLoading: isPublished ? rawAPI.isLoading : query.isLoading
    }
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
        props.setTitle({
            value: 'Subscriptions',
            noThumbtack: true,
            children: <VersionBadge />
        })

        return () => props.setTitle(undefined)
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

    const deleteItem = item => client.delete(item)
        .then(() => window.location.reload())


    if (rawSubscriptions.isLoading)
        return <SimpleLoader />

    return <Table
        parentProps={{ params }}
        navigateTo={(item) => history.push(`/apis/${params.apiId}/subscriptions/${item.id}/edit`)}
        navigateOnEdit={(item) => history.push(`/apis/${params.apiId}/subscriptions/${item.id}/edit`)}
        selfUrl="subscriptions"
        defaultTitle="Subscription"
        itemName="Subscription"
        columns={columns}
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
}

function SubscriptionDesigner(props) {
    const params = useParams()
    const history = useHistory()

    const [subscription, setSubscription] = useState()

    const { item, isLoading } = useDraftOfAPI()

    const rawSubscription = useQuery(["getSubscription", params.subscriptionId],
        () => nextClient.forEntityNext(nextClient.ENTITIES.API_CONSUMER_SUBSCRIPTIONS).findById(params.subscriptionId),
        {
            onSuccess: setSubscription
        }
    )

    // prevent schema to have a empty consumers list
    if (isLoading || !subscription)
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
                options: item.consumers,
                optionsTransformer: {
                    value: 'id',
                    label: 'name'
                }
            }
        },
        token_refs: {
            array: true,
            label: 'Token refs',
            type: 'string'
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

    if (isLoading || rawSubscription.isLoading)
        return <SimpleLoader />

    return <>
        <PageTitle title={subscription.name} {...props}>
            <FeedbackButton
                type="success"
                className="d-flex ms-auto"
                onPress={updateSubscription}
                text={<>
                    Update <VersionBadge size="xs" />
                </>}
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
    </>
}

function NewSubscription(props) {
    const params = useParams()
    const history = useHistory()

    const [subscription, setSubscription] = useState()
    const [error, setError] = useState()

    const { item, isLoading } = useDraftOfAPI()

    const templatesQuery = useQuery(["getTemplate"],
        () => nextClient.forEntityNext(nextClient.ENTITIES.API_CONSUMER_SUBSCRIPTIONS).template(),
        {
            enabled: !!item,
            onSuccess: sub => setSubscription({
                ...sub,
                consumer_ref: item.consumers?.length > 0 ? item.consumers[0]?.id : undefined
            })
        }
    )

    // prevent schema to have a empty consumers list
    if (isLoading || !subscription)
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
                options: item.consumers,
                optionsTransformer: consumers => {
                    return consumers.map(consumer => ({
                        value: consumer.id,
                        label: `${consumer.name} [${consumer.status}]`
                    }))
                }
            }
        },
        token_refs: {
            array: true,
            label: 'Token refs',
            type: 'string'
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
        const consumer = item.consumers.find(consumer => consumer.id === subscription.consumer_ref)

        if (consumer.state === 'staging' || consumer.state === 'closed') {
            return alert('attention on est en staging')
        }

        return nextClient
            .forEntityNext(nextClient.ENTITIES.API_CONSUMER_SUBSCRIPTIONS)
            .create({
                ...subscription,
                api_ref: params.apiId
            })
            .then(res => {
                if (res && res.error) {
                    if (res.error.includes('wrong status')) {
                        setError("You can't subscribe to an unpublished consumer")
                    } else {
                        setError(res.error)
                    }
                    throw res.error
                } else {
                    history.push(`/apis/${params.apiId}/subscriptions`)
                }
            })
    }

    if (isLoading || templatesQuery.isLoading)
        return <SimpleLoader />

    return <>
        <PageTitle title={subscription.name} {...props} />
        <div style={{
            maxWidth: 640,
            margin: 'auto'
        }}>
            <NgForm
                value={subscription}
                schema={schema}
                flow={flow}
                onChange={newSub => {
                    setSubscription(newSub)
                    setError(undefined)
                }} />

            {error && <div
                className="mt-3 p-3"
                style={{
                    borderLeft: '2px solid #D5443F',
                    background: '#D5443F',
                    color: 'var(--text)',
                    borderRadius: '.25rem'
                }}>
                {error}
            </div>}
            <FeedbackButton
                type="success"
                className="d-flex ms-auto mt-3 d-flex align-items-center"
                onPress={updateSubscription}
                text={<>
                    Create <VersionBadge size="xs" />
                </>}
            />
        </div>
    </>
}

function RouteDesigner(props) {
    const params = useParams()
    const history = useHistory()

    const [route, setRoute] = useState()
    const [schema, setSchema] = useState()

    const { item, setItem, updateItem, isLoading } = useDraftOfAPI()

    const [backends, setBackends] = useState([])

    const backendsQuery = useQuery(['getBackends'],
        () => nextClient.forEntityNext(nextClient.ENTITIES.BACKENDS).findAll(),
        {
            enabled: backends.length <= 0,
            onSuccess: setBackends
        })

    useEffect(() => {
        if (item && backendsQuery.data !== undefined) {
            setRoute(item.routes.find(route => route.id === params.routeId))
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
                    label: 'Flow',
                    props: {
                        options: item.flows,
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
                        options: [...item.backends, ...backends],
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
    }, [item, backendsQuery.data])

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
            collapsed: false,
            name: 'Selected flow',
            fields: ['flow_ref'],
        },
        {
            type: 'group',
            collapsable: true,
            collapsed: false,
            name: 'Backend configuration',
            fields: ['backend'],
        },
        {
            type: 'group',
            collapsable: true,
            collapsed: false,
            name: 'Additional informations',
            fields: ['name'],
        }
    ]

    const updateRoute = () => {
        return updateItem({
            ...item,
            routes: item.routes.map(item => {
                if (item.id === route.id)
                    return route
                return item
            })
        })
            .then(() => history.push(`/apis/${params.apiId}/routes`))
    }

    if (!route || isLoading || !schema)
        return <SimpleLoader />

    return <>
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
    </>
}

function NewRoute(props) {
    const params = useParams()
    const history = useHistory()

    const [route, setRoute] = useState()
    const [schema, setSchema] = useState()

    const [backends, setBackends] = useState([])

    const backendsQuery = useQuery(['getBackends'],
        () => nextClient.forEntityNext(nextClient.ENTITIES.BACKENDS).findAll(),
        {
            enabled: backends.length <= 0,
            onSuccess: setBackends
        })

    const { item, updateItem, isLoading } = useDraftOfAPI()

    useEffect(() => {
        if (item && !backendsQuery.isLoading && !schema) {
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
                    flow: NgFrontend.flow
                },
                flow_ref: {
                    type: 'select',
                    label: 'Flow',
                    props: {
                        options: item.flows,
                        optionsTransformer: {
                            label: 'name',
                            value: 'id',
                        }
                    },
                },
                backend: {
                    renderer: props => {
                        // return <BackendSelector
                        //     enabled
                        //     backends={[...item.backends, ...backends]}
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
                        //     usingExistingBackend={props.rootValue.usingExistingBackend}
                        //     route={props.rootValue}
                        // />
                        return <div className="row mb-3">
                            <label className="col-xs-12 col-sm-2 col-form-label" style={{ textAlign: 'right' }}>Backend</label>
                            <div className="col-sm-10">
                                <NgSelectRenderer
                                    id="backend_select"
                                    value={props.rootValue.backend_ref || props.rootValue.backend}
                                    placeholder="Select an existing backend"
                                    label={' '}
                                    ngOptions={{
                                        spread: true,
                                    }}
                                    isClearable
                                    onChange={backend_ref => {
                                        props.rootOnChange({
                                            ...props.rootValue,
                                            usingExistingBackend: true,
                                            backend: backend_ref
                                        })
                                    }}
                                    components={{
                                        Option: props => {
                                            return <div className='d-flex align-items-center m-0 p-2' style={{ gap: '.5rem' }} onClick={() => {
                                                props.selectOption(props.data)
                                            }}>
                                                <span className={`badge ${props.data.value?.startsWith('backend_') ? 'bg-warning' : 'bg-success'}`}>
                                                    {props.data.value?.startsWith('backend_') ? 'GLOBAL' : 'LOCAL'}
                                                </span>{props.data.label}
                                            </div>
                                        },
                                        SingleValue: (props) => {
                                            return <div className='d-flex align-items-center m-0' style={{ gap: '.5rem' }}>
                                                <span className={`badge ${props.data.value?.startsWith('backend_') ? 'bg-warning' : 'bg-success'}`}>
                                                    {props.data.value?.startsWith('backend_') ? 'GLOBAL' : 'LOCAL'}
                                                </span>{props.data.label}
                                            </div>
                                        }
                                    }}
                                    options={[...item.backends, ...backends]}
                                    optionsTransformer={(arr) =>
                                        arr.map((item) => ({ label: item.name, value: item.id }))
                                    }
                                />
                            </div>
                        </div>
                    }
                }
            })
        }
    }, [item, backendsQuery])

    const flow = [
        {
            type: 'group',
            collapsable: true,
            collapsed: false,
            name: '1. Add your domains',
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

    const saveRoute = () => {
        return updateItem({
            ...item,
            routes: [
                ...item.routes, {
                    ...route,
                    id: v4()
                }
            ]
        })
            .then(() => history.push(`/apis/${params.apiId}`))
    }

    const templatesQuery = useQuery(["getTemplates"],
        () => fetch(`/bo/api/proxy/api/frontends/_template`, {
            method: 'GET',
            credentials: 'include',
            headers: {
                Accept: 'application/json',
            },
        }),
        {
            enabled: !isLoading && !!item,
            onSuccess: (frontendTemplate) => {
                setRoute({
                    ...route,
                    name: 'My first route',
                    frontend: frontendTemplate,
                    backend: item.backends.length && item.backends[0].id,
                    usingExistingBackend: true,
                    flow_ref: item.flows.length && item.flows[0].id,
                })
            }
        })

    if (isLoading || !schema || templatesQuery.isLoading || !route)
        return <SimpleLoader />

    return <>
        <PageTitle title="New Route" {...props} style={{ paddingBottom: 0 }} />
        <div style={{
            maxWidth: 640,
            margin: 'auto'
        }}>
            <NgForm
                flow={flow}
                schema={schema}
                value={route}
                onChange={setRoute}
            />
            <FeedbackButton
                type="success"
                className="d-flex mt-3 ms-auto"
                onPress={saveRoute}
                disabled={!route.flow_ref}
                text={<>
                    Create <VersionBadge size="xs" />
                </>}
            />
        </div>
    </>
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

    const { item, updateItem, isLoading } = useDraftOfAPI()

    useEffect(() => {
        props.setTitle({
            value: 'Consumers',
            noThumbtack: true,
            children: <VersionBadge />
        })
        return () => props.setTitle('')
    }, [])

    const deleteItem = newItem => updateItem({
        ...item,
        consumers: item.consumers.filter(f => f.id !== newItem.id)
    })

    if (isLoading || !item)
        return <SimpleLoader />

    return <>
        <Table
            parentProps={{ params }}
            navigateTo={(item) => history.push(`/apis/${params.apiId}/consumers/${item.id}/edit`)}
            navigateOnEdit={(item) => history.push(`/apis/${params.apiId}/consumers/${item.id}/edit`)}
            selfUrl="consumers"
            defaultTitle="Consumer"
            itemName="Consumer"
            columns={columns}
            deleteItem={deleteItem}
            fetchTemplate={() => Promise.resolve({
                id: v4(),
                name: "New consumer",
                consumer_kind: "apikey",
                config: {}
            })}
            fetchItems={() => Promise.resolve(item.consumers || [])}
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
    </>
}

const TEMPLATES = {
    apikey: {
        wipe_backend_request: true,
        validate: true,
        mandatory: true,
        pass_with_user: false,
        update_quotas: true,
    },
    mtls: {
        serialNumbers: [],
        subjectDNs: [],
        issuerDNs: [],
        regexSubjectDNs: [],
        regexIssuerDNs: [],
    },
    keyless: {},
    oauth2: {
        expiration: 3600000,
        default_key_pair: "otoroshi-jwt-signing"
    },
    jwt: {
        verifier: undefined,
        fail_if_absent: false
    }
}

function NewConsumerSettingsForm(props) {
    console.log(props.value)
    return <NgForm
        value={props.value}
        onChange={settings => {
            if (settings && JSON.stringify(props.value, null, 2) !== JSON.stringify(settings, null, 2))
                props.onChange(settings)
        }}
        schema={props.schema}
        flow={props.flow}
    />
}

const CONSUMER_FORM_SETTINGS = {
    schema: {
        name: {
            type: 'string',
            label: 'Name'
        },
        consumer_kind: {
            renderer: props => {
                return <div className="row mb-3">
                    <label className="col-xs-12 col-sm-2 col-form-label" style={{ textAlign: 'right' }}>Consumer kind</label>
                    <div className="col-sm-10">
                        <NgDotsRenderer
                            value={props.value}
                            options={['apikey', 'mtls', 'keyless', 'oauth2', 'jwt']}
                            ngOptions={{
                                spread: true
                            }}
                            onChange={newType => {
                                props.rootOnChange({
                                    ...props.rootValue,
                                    settings: TEMPLATES[newType],
                                    consumer_kind: newType
                                })
                            }}
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
            renderer: props => {
                const kind = props.rootValue.consumer_kind

                const kinds = {
                    jwt: {
                        schema: JwtVerificationOnly.config_schema,
                        flow: JwtVerificationOnly.config_flow,
                    },
                    oauth2: {
                        schema: NgClientCredentialTokenEndpoint.config_schema,
                        flow: NgClientCredentialTokenEndpoint.config_flow,
                    },
                    mtls: {
                        schema: NgHasClientCertMatchingValidator.config_schema,
                        flow: NgHasClientCertMatchingValidator.config_flow,
                    },
                    apikey: {
                        schema: {
                            wipe_backend_request: {
                                label: 'Wipe backend request',
                                type: 'box-bool',
                                props: {
                                    description: 'Remove the apikey fromcall made to downstream service',
                                },
                            },
                            update_quotas: {
                                label: 'Update quotas',
                                type: 'box-bool',
                                props: {
                                    description: 'Each call with an apikey will update its quota',
                                },
                            },
                            pass_with_user: {
                                label: 'Pass with user',
                                type: 'box-bool',
                                props: {
                                    description: 'Allow the path to be accessed via an Authentication module',
                                },
                            },
                            mandatory: {
                                label: 'Mandatory',
                                type: 'box-bool',
                                props: {
                                    description:
                                        'Allow an apikey and and authentication module to be used on a same path. If disabled, the route can be called without apikey.',
                                },
                            },
                            validate: {
                                label: 'Validate',
                                type: 'box-bool',
                                props: {
                                    description:
                                        'Check that the api key has not expired, has not reached its quota limits and is authorized to call the Otoroshi service',
                                },
                            },
                        }
                    }
                }

                const onChange = settings => {
                    if (settings)
                        props.rootOnChange({
                            ...props.rootValue,
                            settings
                        })
                }

                if (kinds[kind])
                    return <NewConsumerSettingsForm
                        schema={kinds[kind].schema}
                        flow={kinds[kind].flow}
                        value={props.rootValue.settings}
                        onChange={onChange}
                    />

                return <JsonObjectAsCodeInput
                    label='Additional informations'
                    onChange={onChange}
                    value={props.rootValue.settings} />
            }
        }
    },
    flow: [{
        type: 'group',
        collapsable: false,
        name: 'Plan',
        fields: ['name',
            'consumer_kind',
            'status',
            'description',
            'auto_validation'
        ],
    },
    {
        type: 'group',
        collapsable: false,
        name: 'Configuration',
        fields: ['settings'],
    }]
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

    const { item, updateItem, isLoading } = useDraftOfAPI()

    const savePlan = () => {
        return updateItem({
            ...item,
            consumers: [...item.consumers, consumer]
        })
            .then(() => history.push(`/apis/${params.apiId}`))
    }

    if (isLoading)
        return <SimpleLoader />

    return <>
        <PageTitle title="New Plan" {...props} style={{ paddingBottom: 0 }} />

        <div style={{
            maxWidth: 640,
            margin: 'auto'
        }}>
            <NgForm
                value={consumer}
                flow={CONSUMER_FORM_SETTINGS.flow}
                schema={CONSUMER_FORM_SETTINGS.schema}
                onChange={newValue => setConsumer(newValue)} />
            <Button
                type="success"
                className="btn-sm ms-auto d-flex align-items-center"
                onClick={savePlan}
            >
                Create <VersionBadge size="xs" className="ms-2" />
            </Button>
        </div>
    </>
}

function ConsumerDesigner(props) {
    const params = useParams()
    const history = useHistory()

    const [consumer, setConsumer] = useState()

    const { item, updateItem, isLoading } = useDraftOfAPI()

    useEffect(() => {
        if (item && !consumer) {
            setConsumer(item.consumers.find(item => item.id === params.consumerId))
        }
    }, [item])

    const updatePlan = () => {
        return updateItem({
            ...item,
            consumers: item.consumers.map(item => {
                if (item.id === consumer.id)
                    return consumer
                return item
            })
        })
            .then(() => history.push(`/apis/${params.apiId}`))
    }

    if (isLoading || !consumer)
        return <SimpleLoader />


    return <>
        <PageTitle title={`Update ${consumer?.name}`} {...props} style={{ paddingBottom: 0 }}>
            <FeedbackButton
                type="success"
                className="ms-2 mb-1 d-flex align-items-center"
                onPress={updatePlan}
                text={<>
                    Update <VersionBadge size="xs" className="ms-2" />
                </>}
            />
        </PageTitle>

        <div style={{
            maxWidth: 640,
            margin: 'auto'
        }}>
            <NgForm
                value={consumer}
                flow={CONSUMER_FORM_SETTINGS.flow}
                schema={CONSUMER_FORM_SETTINGS.schema}
                onChange={newValue => setConsumer(newValue)} />
        </div>
    </>
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
        {
            title: 'Frontend',
            filterId: 'frontend.domains.0',
            cell: (item, a) => {
                return (
                    <>
                        {item.frontend.domains[0] || '-'}{' '}
                        {item.frontend.domains.length > 1 && (
                            <span
                                className="badge bg-secondary"
                                style={{ cursor: 'pointer' }}
                                title={item.frontend.domains.map((v) => ` - ${v}`).join('\n')}
                            >
                                {item.frontend.domains.length - 1} more
                            </span>
                        )}
                    </>
                );
            },
        },
    ];

    const { item, updateItem, isLoading } = useDraftOfAPI()

    useEffect(() => {
        props.setTitle({
            value: 'Routes',
            noThumbtack: true,
            children: <VersionBadge />
        })

        return () => props.setTitle(undefined)
    }, [])

    const client = nextClient.forEntityNext(nextClient.ENTITIES.APIS)

    const deleteItem = newItem => {
        return updateItem({
            ...item,
            routes: item.routes.filter(f => f.id !== newItem.id)
        })
    }

    if (isLoading)
        return <SimpleLoader />

    return <Table
        parentProps={{ params }}
        navigateTo={(item) => history.push(`/apis/${params.apiId}/routes/${item.id}/edit`)}
        navigateOnEdit={(item) => history.push(`/apis/${params.apiId}/routes/${item.id}/edit`)}
        selfUrl="routes"
        defaultTitle="Route"
        itemName="Route"
        columns={columns}
        deleteItem={deleteItem}
        fetchTemplate={client.template}
        fetchItems={() => Promise.resolve(item.routes || [])}
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
        //     title: 'Backend',
        // filterId: 'backend.targets.0.hostname',
        // cell: (item) => {
        //   return (
        //     <>
        //       {item.backend.targets[0]?.hostname || '-'}{' '}
        //       {item.backend.targets.length > 1 && (
        //         <span
        //           className="badge bg-secondary"
        //           style={{ cursor: 'pointer' }}
        //           title={item.backend.targets
        //             .map((v) => ` - ${v.tls ? 'https' : 'http'}://${v.hostname}:${v.port}`)
        //             .join('\n')}
        //         >
        //           {item.backend.targets.length - 1} more
        //         </span>
        //       )}
        //     </>
        //   );
        // },
    ];

    const { item, updateItem, isLoading } = useDraftOfAPI()

    useEffect(() => {
        props.setTitle({
            value: 'Backends',
            noThumbtack: true,
            children: <VersionBadge />
        })

        return () => props.setTitle('')
    }, [])

    const client = nextClient.forEntityNext(nextClient.ENTITIES.BACKENDS)

    const deleteItem = newItem => updateItem({
        ...item,
        backends: item.backends.filter(f => f.id !== newItem.id)
    })

    if (isLoading)
        return <SimpleLoader />

    return <Table
        parentProps={{ params }}
        navigateTo={(item) => history.push(`/apis/${params.apiId}/backends/${item.id}/edit`)}
        navigateOnEdit={(item) => history.push(`/apis/${params.apiId}/backends/${item.id}/edit`)}
        selfUrl="backends"
        defaultTitle="Backend"
        itemName="Backend"
        columns={columns}
        deleteItem={deleteItem}
        fetchTemplate={client.template}
        fetchItems={() => Promise.resolve(item.backends || [])}
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
}

function NewBackend(props) {
    const params = useParams()
    const history = useHistory()

    const [backend, setBackend] = useState()

    const { item, updateItem, isLoading } = useDraftOfAPI()

    const saveBackend = () => {
        return updateItem({
            ...item,
            backends: [...item.backends, {
                ...backend,
                ...backend.backend
            }]
        })
            .then(() => history.push(`/apis/${params.apiId}/backends`))
    }

    const templateQuery = useQuery(["getTemplate"],
        nextClient.forEntityNext(nextClient.ENTITIES.BACKENDS).template, {
        retry: 0,
        onSuccess: (data) => setBackend({
            id: v4(),
            name: 'My new backend',
            backend: data.backend
        })
    });

    if (templateQuery.isLoading || isLoading)
        return <SimpleLoader />

    return <>
        <PageTitle title="New Backend" {...props} style={{ paddingBottom: 0 }}>
            <FeedbackButton
                type="success"
                className="ms-2 mb-1 d-flex align-items-center"
                onPress={saveBackend}
                text={<>
                    Create <VersionBadge size="xs" />
                </>}
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
    </>
}

function EditBackend(props) {
    const params = useParams()
    const history = useHistory()

    const { item, updateItem, isLoading } = useDraftOfAPI()

    const [backend, setBackend] = useState()

    useEffect(() => {
        if (item && !backend) {
            setBackend(item.backends.find(item => item.id === params.backendId))
        }
    }, [item])

    const updateBackend = () => {
        return updateItem({
            ...item,
            backends: item.backends.map(item => {
                if (item.id === backend.id)
                    return backend
                return item
            })
        })
            .then(() => history.push(`/apis/${params.apiId}/backends`))
    }

    if (isLoading)
        return <SimpleLoader />

    return <>
        <PageTitle title="Update Backend" {...props} style={{ paddingBottom: 0 }}>
            <FeedbackButton
                type="success"
                className="ms-2 mb-1 d-flex align-items-center"
                onPress={updateBackend}
                text={<>
                    Update <VersionBadge size="xs" />
                </>}
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
    </>
}

function Testing(props) {
    const { item, version, updateItem, setItem, isLoading } = useDraftOfAPI()

    if (version === 'Published') {
        return <div>
            Testing mode is only available in the draft version
        </div>
    }

    if (isLoading)
        return null

    const schema = {
        enabled: {
            type: 'box-bool',
            label: 'Enabled',
            props: {
                description: 'When enabled, this option allows draft routes to be exposed. These routes can be accessed using a specific header, ensuring they remain available only for testing purposes.',
            },
        },
        config: {
            renderer: props => {
                return <div className="row mb-3">
                    <label className="col-xs-12 col-sm-2 col-form-label" style={{ textAlign: 'right' }}>
                        Configuration
                    </label>
                    <div className="col-sm-10">
                        Add this header to your calls
                        <div className='d-flex flex-column gap-2 mt-3'>
                            <input className="form-control" readOnly type="text" value={props.rootValue?.headerKey} />
                            <input className="form-control" readOnly type="text" value={props.rootValue?.headerValue} />
                        </div>
                    </div>
                </div>
            }
        }
    }

    return <>
        <PageTitle title='Testing mode' {...props}>
            <FeedbackButton
                type="success"
                className="d-flex ms-auto"
                onPress={updateItem}
                text={<>
                    Update <VersionBadge size="xs" />
                </>}
            />
        </PageTitle>
        <div style={{
            maxWidth: 640,
            margin: 'auto'
        }}>
            <NgForm
                value={item?.testing}
                onChange={testing => setItem({
                    ...item,
                    testing
                })}
                schema={schema}
            />
        </div>
    </>
}

function Deployments(props) {
    const params = useParams()

    const columns = [
        {
            title: 'Version',
            filterId: 'version',
            content: (item) => item.version,
        },
        {
            title: 'Deployed At',
            filterId: 'at',
            content: (item) => moment(item.at).format('YYYY-MM-DD HH:mm:ss.SSS')
        },
        {
            title: 'Owner',
            filterId: 'owner',
            content: (item) => item.owner
        },
    ];

    const { item, isLoading } = useDraftOfAPI()

    useEffect(() => {
        props.setTitle({
            value: 'Deployments',
            noThumbtack: true,
            children: <VersionBadge />
        })
        return () => props.setTitle(undefined)
    }, [])

    if (isLoading)
        return <SimpleLoader />

    return <Table
        navigateTo={item =>
            window.wizard('Version', () => <PublisDraftModalContent
                draft={item}
                currentItem={item} />, {
                noCancel: true,
                okLabel: 'Close'
            })
        }
        parentProps={{ params }}
        selfUrl="deployments"
        defaultTitle="Deployment"
        itemName="Deployment"
        columns={columns}
        fetchTemplate={() => Promise.resolve({})}
        fetchItems={() => Promise.resolve(item.deployments || [])}
        defaultSort="version"
        defaultSortDesc="true"
        showActions={false}
        extractKey={(item) => item.id}
        rowNavigation={true}
        hideAddItemAction={true}
    />
}

function SidebarWithVersion({ params }) {
    const queryParams = new URLSearchParams(window.location.search)
    const queryVersion = queryParams.get('version')

    useEffect(() => {
        if (queryVersion) {
            updateQueryParams(queryVersion)
            updateSignal(queryVersion)
        }
    }, [queryVersion])

    const updateSignal = version => {
        signalVersion.value = version
    }

    const updateQueryParams = version => {
        const queryParams = new URLSearchParams(window.location.search);
        queryParams.set("version", version);
        history.replaceState(null, null, "?" + queryParams.toString());
    }

    return <Sidebar params={params} />
}

function SidebarComponent(props) {
    const params = useParams()
    const location = useLocation()

    useEffect(() => {
        if (location.pathname !== '/apis') {
            props.setSidebarContent(<SidebarWithVersion params={params} />);
        }
        return () => props.setSidebarContent(null)
    }, [params])

    return null
}

function NewFlow(props) {
    const history = useHistory()
    const params = useParams()

    useEffect(() => {
        props.setTitle({
            value: "Create a new Flow",
            noThumbtack: true,
            children: <VersionBadge />
        })

        return () => props.setTitle(undefined)
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

    const { item, updateItem, isLoading } = useDraftOfAPI()

    const createFlow = () => {
        return updateItem({
            ...item,
            flows: [...item.flows, flow]
        })
            .then(() => history.push(`/apis/${params.apiId}/flows/${flow.id}`));
    }

    if (isLoading)
        return <SimpleLoader />

    return <>
        <Form
            schema={schema}
            flow={["name"]}
            value={flow}
            onChange={setFlow}
        />
        <Button
            type="success"
            className="btn-sm ms-auto d-flex align-items-center"
            onClick={createFlow}
        >
            Create <VersionBadge size="xs" className="ms-2" />
        </Button>
    </>
}

function NewAPI(props) {
    const history = useHistory()

    useEffect(() => {
        props.setTitle({
            value: "Create a new API",
            noThumbtack: true,
            children: <VersionBadge />
        })
        return () => props.setTitle(undefined)
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
        capture: {
            type: 'bool',
            label: 'Capture route traffic',
            props: {
                labelColumn: 3,
            },
        },
        debug_flow: {
            type: 'bool',
            label: 'Debug the route',
            props: {
                labelColumn: 3,
            },
        },
        export_reporting: {
            type: 'bool',
            label: 'Export reporting',
            props: {
                labelColumn: 3,
            },
        },
    }

    const flow = ['location', 'name', 'description']

    const createApi = () => {
        nextClient.forEntityNext(nextClient.ENTITIES.APIS)
            .create(value)
            .then(() => history.push(`/apis/${value.id}`));
    }

    if (template.isLoading)
        return <SimpleLoader />

    return <>
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
    </>
}

function Apis(props) {
    const ref = useRef()
    const params = useParams()
    const history = useHistory()

    useEffect(() => {
        props.setTitle('Apis')
        return () => props.setTitle(undefined)
    }, [])

    const columns = [
        {
            title: 'Name',
            content: item => item.name
        },
        {
            title: 'Id',
            content: item => item.id
        },
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

    const { item, updateItem, isLoading } = useDraftOfAPI()

    const [flow, setFlow] = useState()
    const ref = useRef(flow)

    useEffect(() => {
        ref.current = flow;
    }, [flow])

    useEffect(() => {
        if (item && !flow) {
            setFlow(item.flows.find(flow => flow.id === params.flowId))

            dynamicTitleContent.value = (
                <PageTitle
                    style={{
                        paddingBottom: 0,
                    }}
                    title={item.flows.find(flow => flow.id === params.flowId)?.name}
                    {...props}
                >
                    <FeedbackButton
                        type="success"
                        className="ms-2 mb-1 d-flex align-items-center"
                        onPress={saveFlow}
                        text={<>
                            {isCreation ? 'Create a new flow' : 'Save'} <VersionBadge size="xs" className="ms-2" />
                        </>}
                    />
                </PageTitle>
            );
        }
    }, [item])

    const saveFlow = () => {
        const {
            id, name, plugins
        } = ref.current.value

        return updateItem({
            ...item,
            flows: item.flows.map(flow => {
                if (flow.id === id)
                    return {
                        id, name, plugins
                    }
                return flow
            })
        })
            .then(() => history.replace(`/apis/${params.apiId}/flows`))
    }

    if (isLoading || !flow)
        return <SimpleLoader />

    return <div className='designer'>
        <Designer
            history={history}
            value={flow}
            setValue={value => setFlow({ value })}
            setSaveButton={() => { }}
        />
    </div>
}

function Flows(props) {
    const params = useParams()
    const history = useHistory()

    const { item, updateItem, isLoading } = useDraftOfAPI()

    const columns = [
        {
            title: 'Name',
            content: item => item.name
        }
    ];

    useEffect(() => {
        props.setTitle({
            value: 'Flows',
            noThumbtack: true,
            children: <VersionBadge />
        })

        return () => props.setTitle(undefined)
    }, [])

    const fetchItems = (paginationState) => Promise.resolve(item.flows)

    const fetchTemplate = () => Promise.resolve({
        id: uuid(),
        name: 'My new flow',
        plugins: []
    })

    const deleteItem = deletedFlow => {
        return updateItem({
            ...item,
            flows: item.flows.filter(flow => flow.id !== deletedFlow.id)
        })
    }

    if (isLoading)
        return <SimpleLoader />

    return <Table
        parentProps={{ params }}
        navigateTo={(item) => history.push(`/apis/${params.apiId}/flows/${item.id}/edit`)}
        navigateOnEdit={(item) => history.push(`/apis/${params.apiId}/flows/${item.id}/edit`)}
        selfUrl={`/apis/${params.apiId}/flows`}
        defaultTitle="Flow"
        itemName="Flow"
        columns={columns}
        deleteItem={deleteItem}
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
}

// function VersionManagerSelector({ createOrUpdate, setCreateOrUpdate }) {
//     return <div className='d-flex flex-column mt-3'
//         style={{ gap: '.25rem' }}>
//         {[
//             {
//                 kind: 'create',
//                 title: 'NEW',
//                 text: 'Create a new version from the current draft',
//             },
//             {
//                 kind: 'update',
//                 title: 'UPDATE',
//                 text: 'Erase the current published version',
//             }
//         ].map(({ kind, title, text }) => (
//             <button
//                 type="button"
//                 className={`btn py-3 wizard-route-chooser  ${createOrUpdate === kind ? 'btn-primaryColor' : 'btn-quiet'}`}
//                 onClick={() => setCreateOrUpdate(kind)}
//                 key={kind}
//             >
//                 <h3 className="wizard-h3--small">{title}</h3>
//                 <span
//                     style={{
//                         flex: 1,
//                         display: 'flex',
//                         alignItems: 'center',
//                     }}
//                 >
//                     {text}
//                 </span>
//             </button>
//         ))}
//     </div>
// }

function VersionManager({ api, draft, owner, setState }) {

    const [deployment, setDeployment] = useState({
        location: {},
        apiRef: api.id,
        owner,
        at: Date.now(),
        apiDefinition: {
            ...draft.content,
            deployments: []
        },
        draftId: draft.id,
        action: 'patch',
        version: semver.inc(api.version, 'patch')
    })

    const schema = {
        location: {
            type: 'location'
        },
        version: {
            type: 'string',
            label: 'Version'
        },
        action: {
            renderer: (props) => {
                const version = props.rootValue?.version

                const nextVersions = {
                    [semver.inc(api.version, 'patch')]: 'patch',
                    [semver.inc(api.version, 'minor')]: 'minor',
                    [semver.inc(api.version, 'major')]: 'major'
                }

                return <div>
                    <NgDotsRenderer
                        value={nextVersions[version]}
                        options={['patch', 'minor', 'major']}
                        schema={{
                            props: {
                                label: 'Action'
                            }
                        }}
                        onChange={action => {
                            if (action === 'patch') {
                                props.rootOnChange({
                                    ...props.rootValue,
                                    version: semver.inc(api.version, 'patch')
                                })
                            } else if (action === 'minor') {
                                props.rootOnChange({
                                    ...props.rootValue,
                                    version: semver.inc(api.version, 'minor')
                                })
                            } else {
                                props.rootOnChange({
                                    ...props.rootValue,
                                    version: semver.inc(api.version, 'major')
                                })
                            }
                        }}
                    />
                </div>
            }
        },
        apiRef: {
            type: 'string',
            props: {
                readOnly: true
            }
        },
        owner: {
            type: 'string',
            label: 'Owner'
        },
        at: {
            type: 'datetime'
        },
        apiDefinition: {
            renderer: () => {
                return <PublisDraftModalContent
                    draft={draft.content}
                    currentItem={api} />
            }
        }
    }

    const { changed, result } = mergeData(api, draft.content)

    const getChanges = () => {
        try {
            return result
                .reduce((acc, item) => {
                    return acc +
                        (item.lineType !== 'none' ? 1 : 0) +
                        (Array.isArray(item.value) ? item.value.reduce((a, i) => a + i.lineType !== 'none' ? 1 : 0, 0) : 0)
                }, 0)
        } catch (err) {
            return "unknown"
        }
    }

    const flow = [
        {
            type: 'group',
            name: 'Informations',
            collapsable: false,
            fields: ['version', 'action', 'owner']
        },
        {
            type: 'group',
            name: !changed ? 'No changes' : `${getChanges()} elements has changed`,
            collapsed: true,
            fields: ['apiDefinition'],
        }
    ]

    return <div className='d-flex flex-column flex-grow gap-3' style={{ maxWidth: 820 }}>
        <NgForm
            value={deployment}
            onChange={data => {
                setDeployment(data)
                setState(data)
            }}
            schema={schema}
            flow={flow} />
        {/* } */}
    </div>
}

function Informations(props) {
    const history = useHistory()

    const { item, setItem, updateItem, isLoading } = useDraftOfAPI()

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
            label: 'Metadata'
        },
        tags: {
            type: 'array',
            label: 'Tags'
        },
        capture: {
            type: 'bool',
            label: 'Capture route traffic',
            props: {
                labelColumn: 3,
            },
        },
        debug_flow: {
            type: 'bool',
            label: 'Debug the route',
            props: {
                labelColumn: 3,
            },
        },
        export_reporting: {
            type: 'bool',
            label: 'Export reporting',
            props: {
                labelColumn: 3,
            },
        },
        danger_zone: {
            renderer: (inputProps) => {
                return (
                    <div className="row mb-3">
                        <label className="col-xs-12 col-sm-2 col-form-label" style={{ textAlign: 'right' }}>
                            Delete this API
                        </label>
                        <div className="col-sm-10">
                            <div style={{ display: 'flex', flexDirection: 'column' }}>
                                <p>Once you delete an API, there is no going back. Please be certain.</p>
                                <Button
                                    style={{ width: 'fit-content' }}
                                    disabled={inputProps.rootValue?.id === props.globalEnv.adminApiId} // TODO
                                    type="danger"
                                    onClick={() => {
                                        window
                                            .newConfirm('Are you sure you want to delete this entity ?')
                                            .then((ok) => {
                                                if (ok) {
                                                    nextClient
                                                        .forEntityNext(nextClient.ENTITIES.APIS)
                                                        .deleteById(inputProps.rootValue?.id)
                                                        .then(() => {
                                                            history.push('/');
                                                        });
                                                }
                                            });
                                    }}
                                >
                                    Delete this API
                                </Button>
                            </div>
                        </div>
                    </div>
                );
            },
        },
    }
    const flow = ['location',
        {
            type: 'group',
            name: 'Route',
            fields: [
                'name',
                'description',
            ],
        },
        {
            type: 'group',
            name: 'Misc.',
            collapsed: true,
            fields: ['tags', 'metadata',
                {
                    type: 'grid',
                    name: 'Flags',
                    fields: ['debug_flow', 'export_reporting', 'capture'],
                }
            ],
        },
        {
            type: 'group',
            name: 'Danger zone',
            collapsed: true,
            fields: ['danger_zone'],
        },]

    const updateAPI = () => {
        updateItem()
            .then(() => history.push(`/apis/${item.id}`));
    }

    useEffect(() => {
        if (item) {
            props.setTitle({
                value: 'Informations',
                noThumbtack: true,
                children: <VersionBadge />
            })

            return () => props.setTitle(undefined)
        }
    }, [item])

    if (isLoading)
        return <SimpleLoader />

    return <>
        <NgForm
            schema={schema}
            flow={flow}
            value={item}
            onChange={setItem}
        />
        <Button
            type="success"
            className="btn-sm ms-auto d-flex align-items-center"
            onClick={updateAPI}>
            Update <VersionBadge size="xs" className="ms-2" />
        </Button>
    </>
}

function VersionBadge({ size, className }) {
    const version = useSignalValue(signalVersion)
    return <div className={className ? className : 'm-0 ms-2'} style={{ fontSize: size === 'xs' ? '.75rem' : '1rem' }}>
        <span className={`badge bg-xs ${version === 'Draft' ? 'bg-warning' : 'bg-danger'}`}>
            {version === 'Published' ? 'PROD' : 'DEV'}
        </span>
    </div>
}

function DashboardTitle({ api, draftWrapper, draft, updateItem, ...props }) {
    const version = useSignalValue(signalVersion)

    return <div className="page-header_title d-flex align-item-center justify-content-between mb-3">
        <div className="d-flex">
            <h3 className="m-0 d-flex align-items-center">Dashboard
                <VersionBadge />
            </h3>
        </div>
        <div className="d-flex align-item-center justify-content-between">
            {version === 'Draft' && <div className='d-flex align-items-center'>
                <Button
                    text="Publish new version"
                    className="btn-sm mx-2"
                    type="primaryColor"
                    style={{
                        borderColor: 'var(--color-primary)',
                    }}
                    onClick={() => {
                        nextClient
                            .forEntityNext(nextClient.ENTITIES.APIS)
                            .findById(props.params.apiId)
                            .then(api => {
                                window
                                    .wizard('Version manager', (ok, cancel, state, setState) => {
                                        return <VersionManager
                                            api={api}
                                            draft={draftWrapper}
                                            owner={props.globalEnv.user}
                                            setState={setState} />
                                    }, {
                                        style: { width: '100%' },
                                        noCancel: false,
                                        okClassName: 'ms-2',
                                        okLabel: 'I want to publish this API',
                                    })
                                    .then(deployment => {
                                        if (deployment) {
                                            fetchWrapperNext(`/${nextClient.ENTITIES.APIS}/${api.id}/deployments`, 'POST', deployment, 'apis.otoroshi.io')
                                                .then(res => {
                                                    console.log(res)
                                                })
                                        }
                                    })
                            })
                    }}
                />
                <Button
                    text="Reset draft"
                    className="btn-sm"
                    type="danger"
                    onClick={() => {
                        window.newConfirm('Are you sure you reset the draft content to match the published version? All your modifications will be discarded.')
                            .then((ok) => {
                                if (ok) {
                                    nextClient.forEntityNext(nextClient.ENTITIES.DRAFTS)
                                        .deleteById(draftWrapper.id)
                                        .then(() => window.location.reload())
                                }
                            })
                    }}
                />
            </div>}
        </div>
    </div>
}

function Dashboard(props) {
    const params = useParams()
    const history = useHistory()

    const { item, draft, draftWrapper, isLoading, version, api, updateItem } = useDraftOfAPI()

    useEffect(() => {
        if (!isLoading && !!draft) {
            props.setTitle(<DashboardTitle {...props}
                params={params}
                api={api}
                draftWrapper={draftWrapper}
                draft={draft}
                updateItem={updateItem} />)
        }

        return () => props.setTitle(undefined)
    }, [item, draft])

    const hasCreateFlow = item && item.flows.length > 0
    const hasCreateRoute = item && item.routes.length > 0
    const hasCreateConsumer = item && item.consumers.length > 0
    const isStaging = item && item.state === API_STATE.STAGING
    const showGettingStarted = !hasCreateFlow || !hasCreateConsumer || !hasCreateRoute || isStaging

    if (isLoading)
        return <SimpleLoader />

    return <div className='d-flex flex-column gap-3' style={{ maxWidth: 1280 }}>
        {item && <>
            <div className='d-flex gap-3'>
                <div className='d-flex flex-column flex-grow gap-3' style={{ maxWidth: 640 }}>
                    {showGettingStarted && <ContainerBlock full>
                        <SectionHeader text="Getting Started" />

                        {isStaging && !hasCreateConsumer && hasCreateRoute && <Card
                            onClick={() => publishAPI(item)}
                            title="Deploy your API"
                            description={<>
                                Start your API and write your first <HighlighedText text="API consumer" link={`/apis/${params.apiId}/consumers`} />
                            </>}
                            button={<FeedbackButton type="primaryColor"
                                className="ms-auto d-flex"
                                onPress={() => publishAPI(item)}
                                text="Start your API" />}
                        />}

                        {!isStaging && hasCreateFlow && hasCreateRoute && !hasCreateConsumer && <Card
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
                                Create group of plugins to apply rules, transformations, and restrictions on routes, enabling advanced traffic control and customization.
                            </>}
                            button={<FeedbackButton type="primaryColor"
                                className="ms-auto d-flex"
                                onPress={() => { }}
                                text="Create" />}
                        />}
                    </ContainerBlock>}
                    {item.state !== API_STATE.STAGING && <ContainerBlock full highlighted>
                        <APIHeader api={item} version={version} draft={draft} />
                        {version !== 'Draft' && <>
                            <ApiStats url={`/bo/api/proxy/apis/apis.otoroshi.io/v1/apis/${item.id}/live?every=2000`} />

                            <Uptime
                                health={item.health?.today}
                                stopTheCountUnknownStatus={false}
                            />
                            <Uptime
                                health={item.health?.yesterday}
                                stopTheCountUnknownStatus={false}
                            />
                            <Uptime
                                health={item.health?.nMinus2}
                                stopTheCountUnknownStatus={false}
                            />
                        </>}
                    </ContainerBlock>}
                    {hasCreateConsumer && <ContainerBlock full>
                        <SectionHeader
                            text="Subscriptions"
                            description={item.consumers.flatMap(c => c.subscriptions).length <= 0 ? 'Souscriptions will appear here' : ''}
                            actions={<Button
                                type="primaryColor"
                                text="Subscribe"
                                className='btn-sm'
                                onClick={() => history.push(`/apis/${params.apiId}/subscriptions/new`)} />} />

                        <SubscriptionsView api={item} />
                    </ContainerBlock>}

                    {hasCreateConsumer && <ContainerBlock full>
                        <SectionHeader text="API Consumers"
                            description={item.consumers.length <= 0 ? 'API consumers will appear here' : ''}
                            actions={<Button
                                type="primaryColor"
                                text="New Consumer"
                                className='btn-sm'
                                onClick={() => history.push(`/apis/${params.apiId}/consumers/new`)} />} />
                        <ApiConsumersView api={item} />
                    </ContainerBlock>}
                </div>
                {item.flows.length > 0 && item.routes.length > 0 && <ContainerBlock>
                    <SectionHeader text="Build your API" description="Manage entities for this API" />
                    <Entities>
                        <FlowsCard flows={item.flows} />
                        <BackendsCard backends={item.backends} />
                        <RoutesCard routes={item.routes} />
                    </Entities>
                </ContainerBlock>}
            </div>
        </>}
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
        onClick={() => {
            if (!open)
                setOpen(true)
        }}>
        {open && <div className="d-flex justify-content-between gap-2 align-items-center">
            <div style={{ position: 'relative', flex: 1 }}>
                <Button type="primaryColor" className="btn-sm" text="Edit"
                    onClick={e => {
                        e.stopPropagation()
                        history.push(`/apis/${params.apiId}/consumers/${consumer.id}/edit`)
                    }} style={{
                        position: 'absolute',
                        top: '.5rem',
                        right: '.5rem',
                        zIndex: 100
                    }} />
                <JsonObjectAsCodeInput
                    editorOnly
                    showGutter={false}
                    label={undefined}
                    value={consumer} />
            </div>
            <i style={{ minWidth: 40 }} className="fas fa-chevron-up fa-lg short-table-navigate-icon" onClick={() => setOpen(false)} />
        </div>}
        {!open && <>
            <div>{consumer.name}</div>
            <div>{consumer.description}</div>
            <div className={`badge custom-badge bg-${CONSUMER_STATUS_COLORS[consumer.status]}`} style={{
                width: 'fit-content',
                border: 'none'
            }}>{consumer.status}</div>
            <div className="badge custom-badge bg-success" style={{
                border: 'none'
            }}>{consumer.consumer_kind}</div>
            <i className="fas fa-chevron-right fa-lg short-table-navigate-icon" />
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
        onClick={() => {
            if (!open)
                setOpen(true)
        }}>
        {open && <div className="d-flex justify-content-between gap-2 align-items-center">
            <div style={{ position: 'relative', flex: 1 }}>
                <Button type="primaryColor" className="btn-sm" text="Edit"
                    onClick={e => {
                        e.stopPropagation()
                        history.push(`/apis/${params.apiId}/subscriptions/${subscription.id}/edit`)
                    }} style={{
                        position: 'absolute',
                        top: '.5rem',
                        right: '.5rem',
                        zIndex: 100
                    }} />
                <JsonObjectAsCodeInput
                    editorOnly
                    showGutter={false}
                    label={undefined}
                    value={subscription} />
            </div>
            <i
                style={{ minWidth: 40 }}
                className="fas fa-chevron-up fa-lg short-table-navigate-icon"
                onClick={() => setOpen(false)} />
        </div>}
        {!open && <>
            <div>{subscription.name}</div>
            <div>{subscription.description}</div>
            <div>{moment(new Date(subscription.dates.created_at)).format('DD/MM/YY hh:mm')}</div>
            <div className='badge custom-badge bg-success' style={{ border: 'none' }}>{subscription.subscription_kind}</div>
            <i className="fas fa-chevron-right fa-lg short-table-navigate-icon" />
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

function publishAPI(api) {
    return nextClient
        .forEntityNext(nextClient.ENTITIES.APIS)
        .update({
            ...api,
            state: API_STATE.PUBLISHED
        })
        .then(() => window.location.reload())
}

function APIHeader({ api, version, draft }) {
    const updateAPI = newAPI => {
        return nextClient
            .forEntityNext(nextClient.ENTITIES.APIS)
            .update(newAPI)
    }

    return <>
        <div className='d-flex align-items-center gap-3'>
            <h2 className='m-0'>{api.name}</h2>
            <span className='badge custom-badge api-status-started' style={{
                fontSize: '.75rem'
            }}>
                {api.version}
            </span>
            {version === 'Draft' && <span className='badge custom-badge api-status-started d-flex align-items-center gap-2'>
                <div className={`testing-dot ${draft.testing?.enabled ? 'testing-dot--enabled' : 'testing-dot--disabled'}`}></div>
                {draft.testing?.enabled ? 'Testing enabled' : 'Testing disabled'}
            </span>}
            <APIState value={api.state} />

            {version !== 'Draft' && <>
                {api.state === API_STATE.STAGING && <Button
                    type='primaryColor'
                    onClick={() => publishAPI(api)}
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
            </>}
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
        return <span className='badge custom-badge api-status-started'>
            <i className='fas fa-rocket me-2' />
            Staging
        </span>

    if (value === API_STATE.DEPRECATED)
        return <span className='badge custom-badge api-status-deprecated'>
            <i className='fas fa-warning me-2' />
            Deprecated
        </span>

    if (value === API_STATE.PUBLISHED)
        return <span className='badge custom-badge api-status-published'>
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

function Card({ title, description, to, button, onClick }) {
    const history = useHistory()

    return <div
        className="cards apis-cards cards--large mb-3"
        onClick={() => {
            onClick ? onClick : history.push(to)
        }}>
        <div className="cards-body">
            <div className='cards-title d-flex align-items-center justify-content-between'>
                {title}
            </div>
            <p className="cards-description" style={{ position: 'relative' }}>
                {description}
                {button ? button : <i className='fas fa-chevron-right fa-lg navigate-icon' />}
            </p>
        </div>
    </div>
}

function BackendsCard({ backends }) {
    const params = useParams()
    const history = useHistory()

    return <div onClick={() => history.push(`/apis/${params.apiId}/backends`)} className="cards apis-cards">
        <div className="cards-body">
            <div className='cards-title d-flex align-items-center justify-content-between'>
                Backends <span className='badge custom-badge api-status-deprecated'>
                    <i className='fas fa-microchip me-2' />
                    {backends.length}
                </span>
            </div>
            <p className="cards-description" style={{ position: 'relative' }}>
                Design robust, scalable <HighlighedBackendText plural /> with optimized performance, security, and seamless front-end integration.
                <i className='fas fa-chevron-right fa-lg navigate-icon' />
            </p>
        </div>
    </div>
}

function RoutesCard({ routes }) {
    const params = useParams()
    const history = useHistory()

    return <div onClick={() => history.push(`/apis/${params.apiId}/routes`)} className="cards apis-cards">
        <div className="cards-body">
            <div className='cards-title d-flex align-items-center justify-content-between'>
                Routes <span className='badge custom-badge api-status-deprecated'>
                    <i className='fas fa-road me-2' />
                    {routes.length}
                </span>
            </div>
            <p className="cards-description relative">
                Define your <HighlighedRouteText />: connect <HighlighedFrontendText plural /> to <HighlighedBackendText plural /> and customize behavior with <HighlighedFlowsText plural /> like authentication, rate limiting, and transformations.
                <i className='fas fa-chevron-right fa-lg navigate-icon' />
            </p>
        </div>
    </div>
}

function FlowsCard({ flows }) {
    const params = useParams()
    const history = useHistory()

    return <div onClick={() => history.push(`/apis/${params.apiId}/flows`)} className="cards apis-cards">
        <div className="cards-body">
            <div className='cards-title d-flex align-items-center justify-content-between'>
                Flows <span className='badge custom-badge api-status-deprecated'>
                    <i className='fas fa-road me-2' />
                    {flows.length}
                </span>
            </div>
            <p className="cards-description relative">
                Create groups of <HighlighedPluginsText plural /> to apply rules, transformations, and restrictions on <HighlighedRouteText plural />, enabling advanced traffic control and customization.
                <i className='fas fa-chevron-right fa-lg navigate-icon' />
            </p>
        </div>
    </div>
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