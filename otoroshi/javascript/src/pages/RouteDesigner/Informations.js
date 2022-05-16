import React, { useEffect, useState } from 'react';
import { Form, type, constraints, format } from '@maif/react-forms';
import { Location } from '../../components/Location';
import { nextClient } from '../../services/BackOfficeServices';
import { useHistory } from 'react-router-dom';
import { useEntityFromURI } from '../../util';
import { isEqual, merge } from 'lodash';
import { FeedbackButton } from './FeedbackButton';
import { Collapse } from '../../components/inputs/Collapse';

export const Informations = ({ isCreation, value, setValue, setSaveButton }) => {
  const history = useHistory();
  const [informations, setInformations] = useState({ ...value });

  const { capitalize, lowercase, fetchName, link } = useEntityFromURI();

  useEffect(() => {
    setInformations({ ...value });
  }, [value]);

  useEffect(() => {
    setSaveButton(saveButton());
  }, [informations]);

  const saveButton = () => {
    return (
      <FeedbackButton
        className="ms-2"
        onPress={saveRoute}
        text={isCreation ? 'Create route' : 'Save route'}
        disabled={isEqual(informations, value)}
        icon={() => <i className="fas fa-paper-plane" />}
      />
    );
  };

  const saveRoute = () => {
    if (isCreation) {
      return nextClient
        .create(nextClient.ENTITIES[fetchName], informations)
        .then(() => history.push(`/${link}/${informations.id}?tab=flow`));
    } else
      return nextClient.update(nextClient.ENTITIES[fetchName], informations).then((res) => {
        if (!res.error) setValue(res);
      });
  };

  const schema = {
    id: {
      type: type.string,
      visible: false,
    },
    name: {
      type: type.string,
      label: `${capitalize} name`,
      placeholder: `Your ${lowercase} name`,
      help: `The name of your ${lowercase}. Only for debug and human readability purposes.`,
      constraints: [constraints.required()],
    },
    enabled: {
      type: type.bool,
      label: 'Route enabled',
    },
    capture: {
      type: type.bool,
      label: 'Capture route traffic',
    },
    debug_flow: {
      type: type.bool,
      label: 'Debug the flow',
    },
    export_reporting: {
      type: type.bool,
      label: 'Export reporting',
    },
    description: {
      type: type.string,
      label: 'Description',
      placeholder: 'Your route description',
      help: 'The description of your route. Only for debug and human readability purposes.',
    },
    groups: {
      type: type.string,
      format: format.select,
      createOption: true,
      isMulti: true,
      label: 'Groups',
    },
    metadata: {
      type: type.object,
      label: 'Metadata',
    },
    tags: {
      type: type.string,
      format: format.select,
      createOption: true,
      isMulti: true,
      label: 'Tags',
    },
    _loc: {
      type: type.object,
      label: null,
      render: ({ onChange, value }) => (
        <Location
          {...value}
          onChangeTenant={(v) =>
            onChange({
              ...value,
              tenant: v,
            })
          }
          onChangeTeams={(v) =>
            onChange({
              ...value,
              teams: v,
            })
          }
        />
      ),
    },
  };

  const flow = [
    {
      label: 'Location',
      flow: ['_loc'],
      collapsed: false,
    },
    'id',
    'name',
    'enabled',
    'debug_flow',
    'export_reporting',
    'capture',
    'description',
    'groups',
    {
      label: 'Advanced',
      flow: ['metadata', 'tags'],
      collapsed: false,
    },
  ];

  if (!informations || !value) return null;

  return (
    <>
      <Form
        schema={schema}
        flow={flow}
        value={informations}
        options={{ autosubmit: true }}
        onSubmit={(item) => setInformations({ ...merge({ ...value }, item) })}
        footer={() => null}
      />
      {!isCreation && (
        <Collapse collapsed={false} initCollapsed={false} label="Delete this route" lineEnd={true}>
          <div className="row mb-3">
            <label className="col-xs-12 col-sm-2 col-form-label" />
            <div className="col-sm-10">
              <button
                className="btn btn-sm btn-danger me-3"
                onClick={() => {
                  window.newConfirm('Are you sure you want to delete that route ?').then((ok) => {
                    if (ok) {
                      nextClient
                        .deleteById(nextClient.ENTITIES[fetchName], value.id)
                        .then(() => history.push(`/${link}`));
                    }
                  });
                }}>
                <i className="fas fa-trash" /> Delete
              </button>
            </div>
          </div>
        </Collapse>
      )}
      <div className="d-flex align-items-center justify-content-end mt-3">
        <button className="btn btn-sm btn-danger" onClick={() => history.push(`/${link}`)}>
          <i className="fas fa-times" /> Cancel
        </button>
        {saveButton()}
      </div>
    </>
  );
};
