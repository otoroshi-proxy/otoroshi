import React, { useEffect, useState } from 'react';
import * as BackOfficeServices from '../../services/BackOfficeServices';
import { TextInput } from '../../components/inputs';
import { LabelAndInput, NgForm } from '../../components/nginputs';
import { Button } from '../../components/Button';
import Loader from '../../components/Loader';
import { useHistory } from 'react-router-dom';

function WizardStepButton(props) {
  return <Button
    {...props}
    type='save'
    style={{
      backgroundColor: '#f9b000',
      borderColor: '#f9b000',
      padding: '12px 48px'
    }}
  />
}

function Breadcrumb({ value, onClick }) {
  return <div className='d-flex'>{value.map((part, i) => {
    return <span
      key={part}
      style={{
        cursor: 'pointer',
        maxWidth: 200,
        whiteSpace: 'pre',
        textOverflow: 'ellipsis',
        overflow: 'hidden'
      }}
      onClick={() => onClick(i)}>
      {part}
      {(i + 1) < value.length && <i className='fas fa-chevron-right mx-1' />}
    </span>
  })}</div>
}

function Header({ onClose, mode }) {
  return <label style={{ fontSize: '1.15rem' }}>
    <i
      className="fas fa-times me-3"
      onClick={onClose}
      style={{ cursor: 'pointer' }}
    />
    <span>{`${mode === 'selector' ? 'Choose your program' : 'Create a new JWT Verifier'}`}</span>
  </label>
}

function WizardActions({ nextStep, prevStep, step }) {
  return <div className="d-flex mt-auto justify-content-between align-items-center">
    {step !== 1 && <label style={{ color: '#f9b000' }} onClick={prevStep}>
      <Button type='outline-save'
        text="Previous"
      />
    </label>}
    <WizardStepButton
      className="ms-auto"
      onClick={nextStep}
      text='Continue' />
  </div>
}

export class JwtVerifierWizard extends React.Component {
  state = {
    step: 1,
    jwtVerifier: {},
    breadcrumb: [
      'Informations'
    ],
    mode: 'selector'
  }

  onChange = (field, value) => {
    this.setState({
      jwtVerifier: {
        ...this.state.jwtVerifier,
        [field]: value
      }
    })
  }

  prevStep = () => {
    if (this.state.step - 1 > 0)
      this.setState({ step: this.state.step - 1 });
  };

  nextStep = () => {
    this.setState({
      step: this.state.step + 1
    });
  };

  updateBreadcrumb = (value, i) => {
    if (i >= this.state.breadcrumb.length) {
      this.setState({
        breadcrumb: [...this.state.breadcrumb, value]
      });
    }
    else {
      this.setState({
        breadcrumb: this.state.breadcrumb.map((v, j) => {
          if (j === i)
            return value
          return v
        })
      })
    }
  }

  render() {
    const { step, jwtVerifier, mode } = this.state;


    const STEPS = [
      {
        component: InformationsStep,
        visibleOnStep: 1,
        props: {
          name: jwtVerifier.name,
          onChange: value => {
            this.onChange('name', value)
            this.updateBreadcrumb(value, 0);
          }
        }
      },
      {
        component: StrategyStep,
        visibleOnStep: 2,
        props: {
          value: jwtVerifier.strategy?.type,
          onChange: value => {
            if (value?.strategy)
              this.updateBreadcrumb(value.strategy, 1);
            this.setState({
              jwtVerifier: {
                ...jwtVerifier,
                strategy: {
                  ...(jwtVerifier.strategy || {}),
                  type: value?.strategy
                }
              }
            }, () => {
              if (value?.strategy)
                this.nextStep()
            })
          }
        }
      },
      {
        component: DefaultTokenStep,
        visibleOnStep: 3,
        onChange: () => {
          this.updateBreadcrumb(`${this.state.jwtVerifier.source?.type || 'Unknown'} Location`, 2);
        }
      },
      {
        component: TokenSignatureStep,
        visibleOnStep: 4,
        props: {
          root: 'algoSettings',
          value: jwtVerifier,
          onChange: value => this.setState({ jwtVerifier: value }, () => {
            this.updateBreadcrumb(`${this.state.jwtVerifier.algoSettings?.type || 'Unknown'} Algo.`, 3);
          })
        }
      },
      {
        component: TokenSignatureStep,
        visibleOnStep: 5,
        condition: value => ['Sign', 'Transform'].includes(value.strategy?.type),
        props: {
          value: jwtVerifier['strategy'],
          root: 'algoSettings',
          title: 'Resign token with',
          onChange: value => this.setState({
            jwtVerifier: {
              ...jwtVerifier,
              ['strategy']: value
            }
          }, () => {
            this.updateBreadcrumb(`${this.state.jwtVerifier.strategy?.algoSettings?.type || 'Unknown'} Resign Algo.`, 4);
          })
        }
      },
      {
        component: TokenTransformStep,
        visibleOnStep: 6,
        condition: value => 'Transform' === value.strategy?.type,
        props: {
          value: jwtVerifier.strategy?.transformSettings,
          onChange: value => {
            this.setState({
              jwtVerifier: {
                ...jwtVerifier,
                strategy: {
                  ...(jwtVerifier.strategy || {}),
                  transformSettings: value
                }
              }
            }, () => {
              const transformSettings = this.state.jwtVerifier.strategy?.transformSettings || {};
              const sameLocation = transformSettings.location === undefined ? true : transformSettings.location;
              const outLocation = transformSettings.out_location?.source?.type || 'Unknown';
              this.updateBreadcrumb(`${sameLocation ? this.state.jwtVerifier.source?.type : outLocation} Out location.`, 5);
            })
          }
        }
      }
    ];

    const showSummary = !STEPS.find(item => {
      return step === item.visibleOnStep && (item.condition ? item.condition(jwtVerifier) : true)
    });

    return (
      <div className="wizard">
        <div className="wizard-container">
          <div className='d-flex' style={{ flexDirection: 'column', padding: '2.5rem', flex: 1 }}>
            <Header onClose={this.props.hide} mode={mode} />

            {mode === 'selector' &&
              <div className='py-3'>
                <Button
                  type='btn-dark'
                  className="py-3 me-2"
                  style={{ border: '1px solid #f9b000' }}
                  onClick={() => this.setState({ mode: 'creation' })}>
                  <h3 className="wizard-h3--small">NEW</h3>
                  <label
                    style={{
                      flex: 1,
                      display: 'flex',
                      alignItems: 'center',
                    }}>
                    Create a new JWT verifier
                  </label>
                </Button>
                <Button
                  type='btn-dark'
                  className="py-3"
                  style={{ border: '1px solid #f9b000' }}
                  onClick={() => this.setState({ mode: 'editition' })}>
                  <h3 className="wizard-h3--small">EDIT</h3>
                  <label
                    style={{
                      flex: 1,
                      display: 'flex',
                      alignItems: 'center',
                    }}>
                    Use an existing JWT verifier
                  </label>
                </Button>
              </div>
            }

            {mode !== 'selector' && <>
              <Breadcrumb value={this.state.breadcrumb} onClick={i => this.setState({ step: i + 1 })} />

              <div className="wizard-content">
                {STEPS.map(({ component, visibleOnStep, props, condition, onChange }) => {
                  if (step === visibleOnStep && (condition ? condition(jwtVerifier) : true)) {
                    return React.createElement(component, {
                      ...(props || {
                        value: jwtVerifier,
                        onChange: value => this.setState({ jwtVerifier: value }, onChange)
                      }), key: component.Type
                    });
                  } else {
                    return null;
                  }
                })}
                {showSummary && <WizardLastStep
                  breadcrumb={this.state.breadcrumb}
                  value={{
                    ...jwtVerifier,
                    strategy: {
                      ...jwtVerifier.strategy,
                      transformSettings: jwtVerifier.strategy?.type === 'Transform' ? {
                        location: jwtVerifier.strategy?.transformSettings?.location ? jwtVerifier.source : jwtVerifier.strategy?.transformSettings?.out_location?.source
                      } : undefined
                    }
                  }} />}
                {!showSummary && <WizardActions nextStep={this.nextStep} prevStep={this.prevStep} step={step} />}
              </div>
            </>}
          </div>
        </div>
      </div>
    )
  }
}

function WizardLastStep({ value, breadcrumb }) {
  const [verifier, setVerifier] = useState();
  const history = useHistory();

  const [error, setError] = useState(false);
  const [creating, setCreating] = useState(false);

  const create = () => {
    setCreating(true);
    BackOfficeServices.createNewJwtVerifier()
      .then(template => {
        BackOfficeServices.createJwtVerifier({
          ...template,
          name: value.name || 'Default name',
          // strict: value.strategy.type === 'StrictDefaultToken',
          source: value.source,
          algoSettings: {
            ...template.algoSettings,
            ...value.algoSettings,
          },
          strategy: {
            ...template.strategy,
            ...value.strategy,
            // type: value.strategy.type === 'StrictDefaultToken' ? 'DefaultToken' : value.strategy.type
            type: value.strategy.type
          }
        })
          .then(res => {
            if (res.error) {
              setError(true);
            } else {
              setVerifier(template);
            }
          })
      })
  }

  return (
    <>
      <h3 style={{ textAlign: 'center' }} className="mt-3">
        Creation steps
      </h3>

      <div className='d-flex mx-auto' style={{
        flexDirection: 'column'
      }}>
        {breadcrumb.map((part, i) => {
          return <LoaderItem text={i === 0 ? `Informations` : part} timeout={1000 + i * 250} key={part} started={creating} />
        })}
      </div>

      {!creating && <Button type='save'
        className='mx-auto mt-3'
        onClick={create}
      >
        <i className='fas fa-check me-1' />
        Create with all informations
      </Button>}

      {(verifier || error) && <Button type='save'
        className='mx-auto mt-3'
        disabled={error}
        onClick={() => history.push(`/jwt-verifiers/edit/${verifier.id}`)}
      >
        <i className={`fas fa-${error ? 'times' : 'check'} me-1`} />
        {error ? 'Something wrong happened : try to check your configuration' : 'See the created verifier'}
      </Button>}
    </>
  )
}

function InformationsStep({ name, onChange }) {
  return (
    <>
      <h3>Let's start with a name for your JWT verifier</h3>

      <div>
        <TextInput
          autoFocus={true}
          placeholder="Your verifier name..."
          flex={true}
          className="my-3"
          style={{
            fontSize: '2em',
            color: '#f9b000',
          }}
          label="Route name"
          value={name}
          onChange={onChange}
        />
      </div>
    </>
  )
}

function StrategyStep({ value, onChange }) {

  const schema = {
    strategy: {
      renderer: props => {
        return <div
          style={{
            display: 'flex',
            gap: '10px',
            flexWrap: 'wrap',
            justifyContent: 'flex-start'
          }}>
          {[
            {
              strategy: 'PassThrough', title: ['Verify'],
              desc: 'PassThrough will only verifiy token signing and fields values if provided. ',
              tags: ['verify']
            },
            {
              strategy: 'Sign', title: ['Verify and re-sign'],
              desc: 'Sign will do the same as PassThrough plus will re-sign the JWT token with the provided algo. settings.',
              tags: ['verify', 'sign']
            },
            {
              strategy: 'Transform', title: ['Verify, re-sign and Transform'],
              desc: 'Transform will do the same as Sign plus will be able to transform the token.',
              tags: ['verify', 'sign', 'transform']
            }
          ].map(({ strategy, desc, title, tags }) => {
            return <Button
              type={value === strategy ? 'save' : 'dark'}
              className="py-3 d-flex align-items-center flex-column col-3"
              style={{
                gap: '12px',
                minHeight: '325px',
                maxWidth: '235px'
              }}
              onClick={() => props.onChange(strategy)}
              key={strategy}
            >
              <div style={{ flex: .2 }}>
                {title.map((t, i) => <h3 className="wizard-h3--small " style={{
                  margin: 0,
                  marginTop: i > 0 ? '1px' : 0
                }} key={t}>
                  {t}
                </h3>)}
              </div>
              <div className='d-flex flex-column align-items-center' style={{ flex: 1 }}>
                <label className='d-flex align-items-center' style={{ textAlign: 'left' }}>
                  {desc}
                </label>
                <div className='mt-auto' style={{
                  padding: '4px',
                  background: '#515151',
                  width: '100%'
                }}>
                  {[
                    'Generate', 'Verify', 'Sign', 'Transform'
                  ]
                    .filter(tag => tags.includes(tag.toLocaleLowerCase()))
                    .map(tag => <div className='d-flex align-items-center me-1'
                      key={tag}
                      style={{
                        minWidth: "80px",
                        padding: '2px 8px 2px 3px'
                      }}>
                      <i className={`fas fa-${tags.includes(tag.toLocaleLowerCase()) ? 'check' : 'times'} me-1`} style={{
                        color: tags.includes(tag.toLocaleLowerCase()) ? '#f9b000' : '#fff',
                        padding: '4px',
                        minWidth: '20px'
                      }} />
                      <span>{tag}</span>
                    </div>)}
                </div>
              </div>
            </Button>
          })}
        </div>
      }
    }
  }

  const flow = [
    'strategy'
  ];

  return (
    <>
      <h3>What kind of strategy will be used</h3>
      <NgForm
        value={value}
        schema={schema}
        flow={flow}
        onChange={onChange}
      />
    </>
  )
}

const TokenLocationForm = {
  schema: {
    source: {
      type: 'form',
      label: 'Source',
      schema: {
        type: {
          type: 'select',
          props: {
            ngOptions: {
              spread: true
            },
            options: [
              { value: 'InHeader', label: 'Header' },
              { value: 'InQueryParam', label: 'Query string' },
              { value: 'InCookie', label: 'Cookie' }
            ]
          }
        },
        name: {
          type: 'string',
          label: 'Name'
        },
        remove: {
          type: 'string',
          placeholder: 'Bearer ',
          label: 'Remove value',
          props: {
            subTitle: '(Optional): String to remove from the value to access to the token'
          }
        },
        debug: {
          renderer: () => {
            return <LabelAndInput label="Examples">
              <NgForm
                schema={{
                  header: {
                    ngOptions: {
                      spread: true
                    },
                    type: 'json',
                    props: {
                      editorOnly: true,
                      height: '50px',
                      defaultValue: {
                        Authorization: 'Bearer XXX.XXX.XXX'
                      }
                    }
                  },
                  result: {
                    type: 'form',
                    label: 'Form values',
                    schema: {
                      headerName: {
                        type: 'string',
                        label: 'Name',
                        props: {
                          disabled: true,
                          defaultValue: 'Authorization'
                        }
                      },
                      remove: {
                        type: 'string',
                        label: 'Remove value',
                        props: {
                          disabled: true,
                          defaultValue: 'Bearer '
                        }
                      },
                    },
                    flow: ['headerName', 'remove']
                  }
                }}
                flow={[
                  {
                    type: 'group',
                    collapsable: false,
                    name: 'A bearer token expected in Authorization header',
                    fields: ['header', 'result']
                  }
                ]} />
            </LabelAndInput>
          }
        }
      },
      flow: [
        'type',
        {
          type: 'group',
          collapsable: false,
          visible: props => props?.type === 'InHeader',
          name: 'Header informations',
          fields: ['name', 'remove', 'debug']
        },
        {
          type: 'group',
          collapsable: false,
          visible: props => props?.type === 'InQueryParam',
          name: 'Query param name',
          fields: ['name']
        },
        {
          type: 'group',
          collapsable: false,
          visible: props => props?.type === 'InCookie',
          name: 'Cookie name',
          fields: ['name']
        }
      ]
    }
  }
}

function DefaultTokenStep({ value, onChange }) {

  return (
    <>
      <h3>The location of the token</h3>
      <NgForm
        value={value}
        schema={TokenLocationForm.schema}
        flow={TokenLocationForm.flow}
        onChange={onChange}
      />
    </>
  )
}

function TokenSignatureStep({ root, value, onChange, title }) {

  const schema = {
    [root]: {
      type: 'form',
      label: 'Signature',
      schema: {
        type: {
          type: 'dots',
          label: 'Algo.',
          props: {
            options: [
              { label: 'Hmac + SHA', value: 'HSAlgoSettings' },
              { label: 'RSASSA-PKCS1 + SHA', value: 'RSAlgoSettings' },
              { label: 'ECDSA + SHA', value: 'ESAlgoSettings' },
              { label: 'JWK Set (only for verification)', value: 'JWKSAlgoSettings' },
              { label: 'RSASSA-PKCS1 + SHA from KeyPair', value: 'RSAKPAlgoSettings' },
              { label: 'ECDSA + SHA from KeyPair', value: 'ESKPAlgoSettings' },
              { label: 'Otoroshi KeyPair from token kid (only for verification)', value: 'KidAlgoSettings' }
            ]
          }
        },
        onlyExposedCerts: {
          type: 'bool',
          label: 'Use only exposed keypairs'
        },
        size: {
          type: 'dots',
          label: 'SHA size',
          props: {
            options: [256, 384, 512]
          }
        },
        secret: {
          type: 'string',
          label: 'HMAC secret'
        },
        base64: {
          type: 'bool',
          label: 'Base64 encoded secret'
        },
        publicKey: {
          type: 'text',
          label: 'Public key'
        },
        privateKey: {
          type: 'text',
          label: 'Private key'
        },
        certId: {
          type: "select",
          label: "Cert. id",
          props: {
            optionsFrom: "/bo/api/proxy/api/certificates",
            optionsTransformer: {
              label: "name",
              value: "id"
            }
          }
        },
        url: {
          type: 'string',
          label: 'URL'
        },
        timeout: {
          type: 'number',
          label: 'HTTP call timeout'
        },
        ttl: {
          type: 'number',
          label: 'Cache TTL for the keyset'
        },
        headers: {
          type: "object",
          label: "Headers"
        },
        kty: {
          type: 'select',
          label: 'Key type',
          props: {
            options: ['RSA', 'EC']
          }
        }
      },
      flow: (props, v) => {
        return {
          KidAlgoSettings: ['type', 'onlyExposedCerts'],
          HSAlgoSettings: ['type', 'size', 'secret', 'base64'],
          RSAlgoSettings: ['type', 'size', 'publicKey', 'privateKey'],
          RSAKPAlgoSettings: ['type', 'size', 'certId'],
          ESKPAlgoSettings: ['type', 'size', 'certId'],
          ESAlgoSettings: ['type', 'size', 'publicKey', 'privateKey'],
          JWKSAlgoSettings: [
            'type',
            'url',
            'timeout',
            'ttl',
            'headers',
            'kty'
          ],
          [undefined]: ['type']
        }[v.value?.type]
      }
    }
  }

  const flow = [root];

  return (
    <>
      <h3>{title || 'Generate token with'}</h3>

      <NgForm
        value={value}
        schema={schema}
        flow={flow}
        onChange={onChange}
      />
    </>
  )
}

function TokenTransformStep({ value, onChange }) {
  const schema = {
    location: {
      type: 'bool',
      label: 'Use the same location than the entry token',
      props: {
        defaultValue: true
      }
    },
    out_location: {
      visible: props => props?.location === false,
      label: 'New location',
      type: 'form',
      ...TokenLocationForm
    }
  }

  const flow = [
    'location',
    'out_location'
  ];

  return (
    <>
      <h3>Location of the generated token</h3>

      <NgForm
        value={value}
        schema={schema}
        flow={flow}
        onChange={onChange}
      />
    </>
  )
}

function LoaderItem({ text, timeout, started }) {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (started) {
      const timeout = setTimeout(() => setLoading(false), timeout);
      return () => timeout;
    }
  }, [started]);

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '42px 1fr',
        minHeight: '42px',
        alignItems: 'center',
        justifyContent: 'flex-start',
        marginBottom: '6px'
      }} className="mt-3">
      {started && <Loader loading={loading} minLoaderTime={timeout}>
        <i className="fas fa-check fa-2x" style={{ color: '#f9b000' }} />
      </Loader>}
      {!started && <i className="fas fa-square fa-2x" />}
      <div
        style={{
          flex: 1,
          marginLeft: '12px',
          color: loading ? '#eee' : '#fff',
          fontWeight: loading ? 'normal' : 'bold',
        }}>
        <div>{text}</div>
      </div>
    </div>
  );
};