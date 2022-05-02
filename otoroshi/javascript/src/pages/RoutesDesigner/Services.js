import React, { useState, useEffect } from 'react'

import { Form } from '@maif/react-forms';
import { nextClient } from '../../services/BackOfficeServices';
import { useRef } from 'react';
import { DEFAULT_FLOW } from '../RouteDesigner/Graph';
import { toUpperCaseLabels } from '../../util';
import { FeedbackButton } from '../RouteDesigner/FeedbackButton';
import { SelectInput } from '@maif/react-forms';
import { CodeInput } from '@maif/react-forms';

const HTTP_COLORS = {
    GET: 'rgb(52, 170, 182)',
    POST: 'rgb(117, 189, 93)',
    DELETE: 'rgb(238, 106, 86)',
    PATCH: '#9b59b6',
    HEAD: '#9b59b6',
    PUT: 'rgb(230, 195, 0)',
    OPTIONS: '#9b59b6'
}

const FolderFrontend = ({ frontend, domain, open }) => {
    const methods = (frontend.methods && frontend.methods.length > 0) ?
        frontend.methods.map((m, i) => <span key={`frontendmethod-${i}`} className={`badge me-1`} style={{ backgroundColor: HTTP_COLORS[m] }}>{m}</span>) :
        [<span className="badge bg-dark">ALL</span>];
    const exact = frontend.exact;
    const end = exact ? '' : (domain.indexOf('/') < 0 ? '/*' : '*');
    const start = 'http://'
    return (
        <div className="d-flex-between">
            {methods.map((method, i) => <div key={`${domain}method${i}`} style={{ minWidth: 34 }}>{method}</div>)}
            <span className='flex ms-2' style={{ fontFamily: 'monospace' }}>{start}{domain}{end}</span>
        </div>
    );
}

const SaveButton = ({ isDirty, saveChanges, disablePadding }) => <div className={`d-flex justify-content-end ${disablePadding ? '' : 'pt-3'}`}>
    <FeedbackButton
        text="Update the route"
        disabled={!isDirty.frontend && !isDirty.backend && !isDirty.backendRef}
        icon={() => <i className="fas fa-paper-plane" />}
        onPress={saveChanges}
    />
</div>

const BackendSelector = ({ setExistingBackend, usingExistingBackend }) => <div className="d-flex mt-2">
    <button
        className="btn btn-sm new-backend-button"
        onClick={() => {
            setExistingBackend(false);
        }}
        style={{ backgroundColor: usingExistingBackend ? '#494849' : '#f9b000' }}>
        Create a new backend
    </button>
    <button
        className="btn btn-sm new-backend-button"
        onClick={() => setExistingBackend(true)}
        style={{ backgroundColor: usingExistingBackend ? '#f9b000' : '#494849' }}>
        Select an existing backend
    </button>
</div>

const RouteForms = ({ frontend, backend, backend_ref, updateRoute, index }) => {
    const frontendRef = useRef()
    const backendRef = useRef()

    const [isDirty, setDirty] = useState({
        frontend: false,
        backend: false,
        backendRef: false
    })
    const [frontendValue, setFrontend] = useState(frontend)
    const [backendValue, setBackend] = useState(backend)
    const [backendRefValue, setBackendRef] = useState(backend_ref)

    const [schemas, setSchemas] = useState()
    const [backends, setBackends] = useState([])
    const [usingExistingBackend, setExistingBackend] = useState(false)
    const [usingJsonView, setJsonView] = useState(false)

    useEffect(() => {
        Promise.all([
            nextClient.form(nextClient.ENTITIES.FRONTENDS),
            nextClient.form(nextClient.ENTITIES.BACKENDS),
            nextClient.find(nextClient.ENTITIES.BACKENDS)
        ]).then(([frontendForm, backendForm, backends]) => {
            setSchemas({
                frontend: {
                    simple: {
                        config_flow: ['domains', 'methods']
                    },
                    advanced: {
                        config_flow: DEFAULT_FLOW.Frontend.config_flow
                    },
                    config_schema: toUpperCaseLabels({
                        ...frontendForm.schema,
                        ...DEFAULT_FLOW.Frontend.config_schema,
                    })
                },
                backend: {
                    simple: {
                        config_flow: ['root', 'targets']
                    },
                    advanced: {
                        config_flow: DEFAULT_FLOW.Backend('').config_flow
                    },
                    config_schema: toUpperCaseLabels(
                        DEFAULT_FLOW.Backend('').config_schema(backendForm.schema)
                    )
                }
            })
            setBackends(backends)
        })
    }, [])

    useEffect(() => {
        setFrontend({
            ...frontend,
            level: 'simple'
        })
    }, [frontend])

    useEffect(() => {
        setBackend({
            ...backend,
            level: 'simple'
        })
    }, [backend])

    useEffect(() => {
        setBackendRef(backend_ref)
    }, [backend_ref])

    const saveChanges = () => {
        return Promise.all([
            frontendRef.current.trigger(),
            backendRef.current.trigger()
        ]).then(([resFrontend, resBackend]) => {
            if (resFrontend && resBackend)
                return updateRoute(index, {
                    frontend: frontendRef.current.methods.data(),
                    backend: backendRef.current.methods.data(),
                    backend_ref: usingExistingBackend ? backendRefValue : null
                })
            else
                return Promise.reject()
        })
    }

    if (!schemas)
        return null

    return <div className='p-2'>
        {!usingJsonView && <div className='d-flex mt-3'>
            <div className='flex p-3 route-forms-form'>
                <h5 className='route-forms-title'>Frontend</h5>
                <RouteForm
                    isDirty={() => isDirty}
                    dirtyField="frontend"
                    setDirty={setDirty}
                    customRef={frontendRef}
                    value={frontendValue}
                    schema={schemas.frontend.config_schema}
                    flow={schemas.frontend[frontendValue.level || 'simple'].config_flow}
                />
                <SaveButton isDirty={isDirty} saveChanges={saveChanges} />
            </div>
            <div className='flex ms-1 p-3 route-forms-form'>
                <h5 className='route-forms-title'>Backend</h5>
                <BackendSelector setExistingBackend={setExistingBackend} usingExistingBackend={usingExistingBackend} />
                {usingExistingBackend && <div className='mt-3'>
                    <SelectInput
                        id="backend_select"
                        value={backendRefValue}
                        placeholder="Select an existing backend"
                        label=""
                        onChange={b => {
                            if (b !== backendRefValue) {
                                console.log('Set dirty from select')
                                setDirty({
                                    ...isDirty,
                                    backendRef: true
                                })
                            }
                            setBackendRef(b)
                        }}
                        possibleValues={backends}
                        transformer={(item) => ({ label: item.name, value: item.id })}
                    />
                </div>}

                {!usingExistingBackend && <RouteForm
                    isDirty={() => isDirty}
                    setDirty={setDirty}
                    dirtyField="backend"
                    customRef={backendRef}
                    value={backendValue}
                    schema={schemas.backend.config_schema}
                    flow={schemas.backend[backendValue.level || 'simple'].config_flow}
                />}
            </div>
        </div>}
        {usingJsonView && <CodeInput
            mode="json"
            themeStyle={{
                maxHeight: '-1',
                minHeight: '100px',
                width: '100%'
            }}
            value={{
                frontendValue,
                backendValue,
                backendRefValue
            }}
            onChange={e => { }}
        />}
        <div className='d-flex justify-content-end pt-3'>
            <button className='btn btn-sm btn-success' onClick={() => setJsonView(!usingJsonView)}>
                {usingJsonView ? 'SIMPLE VIEW' : 'ADVANCED JSON'}
            </button>
            <SaveButton isDirty={isDirty} saveChanges={saveChanges} disablePadding={true} />
        </div>
    </div>
}

const RouteForm = React.memo(({ isDirty, dirtyField, customRef, value, schema, flow, setDirty }) => <Form
    ref={customRef}
    value={value}
    schema={schema}
    flow={flow}
    footer={() => null}
    options={{
        watch: () => {
            if (customRef.current) {
                const formState = Object.keys(customRef.current.methods.formState.dirtyFields).length > 0;
                console.log('Set dirty from customRef')
                setDirty({
                    ...isDirty(),
                    [dirtyField]: formState
                });
            }
        }
    }}
/>, (prev, next) => prev.value === next.value)

const DeleteMessage = ({ onCancel, onConfirm }) => (
    <div class="d-flex align-items-center justify-content-start flex-column p-3">
        <h4>Delete this route ?</h4>
        <div class="d-flex">
            <button type="button" class="btn btn-danger me-1" onClick={onCancel}>Cancel</button>
            <button type="button" class="btn btn-success" onClick={onConfirm}>Delete</button>
        </div>
    </div>
)

const Route = props => {
    const [open, setOpen] = useState(false)
    const [onRemoving, setRemoving] = useState(false)
    const { frontend } = props

    return <div
        className='route-item my-2'
        style={{ minHeight: open ? '200px' : 'initial' }}>
        <div className={`d-flex-between ${open ? 'route-forms-header' : ''}`} style={{
            padding: '6px',
            paddingBottom: open ? '8px' : '6px'
        }}>
            <div className='flex-column'>
                {frontend.domains.map(domain => <FolderFrontend
                    frontend={frontend}
                    domain={domain}
                    open={open} />)}
            </div>
            <div className='d-flex'>
                {open && <button className='btn btn-sm btn-danger me-2' onClick={() => {
                    setOpen(true)
                    setRemoving(true)
                }}>
                    <i className="fas fa-trash" />
                </button>}
                <button className='btn btn-sm' style={{ background: '#f9b000', borderColor: '#f9b000' }}
                    onClick={() => setOpen(!open)} >
                    <i className={`fas fa-chevron-${open ? 'up' : 'down'}`} />
                </button>
            </div>
        </div>
        {onRemoving && <DeleteMessage onCancel={() => {
            setRemoving(false)
        }} onConfirm={props.removeRoute} />}
        {open && !onRemoving && <RouteForms {...props} />}
    </div>

}

export default ({ service }) => {
    const [routes, setRoutes] = useState([])
    const [templates, setTemplates] = useState({})

    useEffect(() => {
        nextClient.template(nextClient.ENTITIES.SERVICES)
            .then(setTemplates);
    }, [])

    useEffect(() => {
        setRoutes(service.routes)
    }, [service.id])

    const updateRoute = (index, item) => {
        return nextClient.update(nextClient.ENTITIES.SERVICES, {
            ...service,
            routes: routes.length === 0 ? [item] : index >= routes.length ? [...routes, item] : routes.map((route, i) => {
                if (i === index)
                    return item
                return route
            })
        })
            .then(s => setRoutes(s.routes))
    }

    const removeRoute = idx => {
        return nextClient.update(nextClient.ENTITIES.SERVICES, {
            ...service,
            routes: routes.filter((_, i) => i !== idx)
        })
    }

    return (
        <div>
            <button className='btn btn-sm btn-success' onClick={() => {
                const newItem = { ...templates?.routes[0] }
                updateRoute(routes.length, newItem)
                    .then(() => setRoutes([...routes, newItem]))
            }}>
                <i className='fas fa-road me-2' />
                Create a new route
            </button>
            <div className=''>
                {routes.map((route, i) => <Route
                    {...route}
                    key={route.id} i
                    ndex={i}
                    updateRoute={updateRoute}
                    removeRoute={() => removeRoute(i)} />
                )}
            </div>
        </div>
    )
}