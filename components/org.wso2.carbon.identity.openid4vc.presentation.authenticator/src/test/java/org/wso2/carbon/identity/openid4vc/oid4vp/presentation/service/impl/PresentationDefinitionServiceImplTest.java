package org.wso2.carbon.identity.openid4vc.oid4vp.presentation.service.impl;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.openid4vc.oid4vp.common.exception.PresentationDefinitionNotFoundException;
import org.wso2.carbon.identity.openid4vc.oid4vp.common.exception.VPException;
import org.wso2.carbon.identity.openid4vc.oid4vp.common.model.PresentationDefinition;
import org.wso2.carbon.identity.openid4vc.oid4vp.presentation.dao.PresentationDefinitionDAO;
import org.wso2.carbon.identity.openid4vc.oid4vp.presentation.service.PresentationDefinitionService;

import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

/**
 * Test class for PresentationDefinitionServiceImpl.
 */
public class PresentationDefinitionServiceImplTest {

    @Mock
    private PresentationDefinitionDAO presentationDefinitionDAO;

    private PresentationDefinitionServiceImpl presentationDefinitionService;

    private static final int TENANT_ID = -1234;
    private static final String DEFINITION_ID = "def-123";
    private static final String DEFINITION_JSON = "{\"id\":\"def-123\",\"input_descriptors\":[{\"id\":\"desc-1\"," +
            "\"constraints\":{\"fields\":[{\"path\":[\"$.credentialSubject.email\"],\"name\":\"email\"}]}}]}";

    @BeforeMethod
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        presentationDefinitionService = new PresentationDefinitionServiceImpl(presentationDefinitionDAO);
    }

    @Test
    public void testCreatePresentationDefinition() throws Exception {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .definitionJson(DEFINITION_JSON)
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.presentationDefinitionExists(DEFINITION_ID, TENANT_ID)).thenReturn(false);
        doNothing().when(presentationDefinitionDAO).createPresentationDefinition(any(PresentationDefinition.class));

        PresentationDefinition created = presentationDefinitionService
                .createPresentationDefinition(definition, TENANT_ID);

        assertNotNull(created);
        assertEquals(created.getDefinitionId(), DEFINITION_ID);
        assertEquals(created.getName(), "Test Def");
    }

    @Test
    public void testCreatePresentationDefinitionMissingName() {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .definitionJson(DEFINITION_JSON)
                .tenantId(TENANT_ID)
                .build();

        assertThrows(VPException.class, () -> presentationDefinitionService
                .createPresentationDefinition(definition, TENANT_ID));
    }

    @Test
    public void testCreatePresentationDefinitionMissingJson() {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .tenantId(TENANT_ID)
                .build();

        assertThrows(VPException.class, () -> presentationDefinitionService
                .createPresentationDefinition(definition, TENANT_ID));
    }

    @Test
    public void testCreatePresentationDefinitionInvalidJson() {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .definitionJson("invalid json")
                .tenantId(TENANT_ID)
                .build();

        assertThrows(VPException.class, () -> presentationDefinitionService
                .createPresentationDefinition(definition, TENANT_ID));
    }

    @Test
    public void testCreatePresentationDefinitionAlreadyExists() throws Exception {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .definitionJson(DEFINITION_JSON)
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.presentationDefinitionExists(DEFINITION_ID, TENANT_ID)).thenReturn(true);

        assertThrows(VPException.class, () -> presentationDefinitionService
                .createPresentationDefinition(definition, TENANT_ID));
    }

    @Test
    public void testGetPresentationDefinitionById() throws Exception {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .definitionJson(DEFINITION_JSON)
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(definition);

        PresentationDefinition result = presentationDefinitionService
                .getPresentationDefinitionById(DEFINITION_ID, TENANT_ID);
        assertNotNull(result);
        assertEquals(result.getDefinitionId(), DEFINITION_ID);
    }

    @Test
    public void testGetPresentationDefinitionByIdNotFound() throws Exception {
        when(presentationDefinitionDAO.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(null);

        assertThrows(PresentationDefinitionNotFoundException.class, () -> presentationDefinitionService
                .getPresentationDefinitionById(DEFINITION_ID, TENANT_ID));
    }

    @Test
    public void testGetPresentationDefinitionByIdEmptyId() throws Exception {
        assertThrows(VPException.class, () -> presentationDefinitionService
                .getPresentationDefinitionById("", TENANT_ID));
    }

    @Test
    public void testGetPresentationDefinitionByResourceId() throws Exception {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .resourceId("res-123")
                .definitionJson(DEFINITION_JSON)
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getPresentationDefinitionByResourceId("res-123", TENANT_ID))
                .thenReturn(definition);

        PresentationDefinition result = presentationDefinitionService
                .getPresentationDefinitionByResourceId("res-123", TENANT_ID);
        assertNotNull(result);
        assertEquals(result.getResourceId(), "res-123");
    }

    @Test
    public void testGetPresentationDefinitionByResourceIdEmpty() throws Exception {
        assertThrows(VPException.class, () -> presentationDefinitionService
                .getPresentationDefinitionByResourceId("", TENANT_ID));
    }

    @Test
    public void testGetAllPresentationDefinitions() throws Exception {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .definitionJson(DEFINITION_JSON)
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getAllPresentationDefinitions(TENANT_ID))
                .thenReturn(Collections.singletonList(definition));

        List<PresentationDefinition> definitions = presentationDefinitionService
                .getAllPresentationDefinitions(TENANT_ID);
        assertNotNull(definitions);
        assertEquals(definitions.size(), 1);
        assertEquals(definitions.get(0).getDefinitionId(), DEFINITION_ID);
    }

    @Test
    public void testUpdatePresentationDefinition() throws Exception {
        PresentationDefinition existingDefinition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Old Name")
                .definitionJson(DEFINITION_JSON)
                .tenantId(TENANT_ID)
                .build();

        PresentationDefinition updateRequest = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("New Name")
                .definitionJson(DEFINITION_JSON)
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID))
                .thenReturn(existingDefinition);
        doNothing().when(presentationDefinitionDAO).updatePresentationDefinition(any(PresentationDefinition.class));

        PresentationDefinition updated = presentationDefinitionService
                .updatePresentationDefinition(updateRequest, TENANT_ID);

        assertNotNull(updated);
        assertEquals(updated.getName(), "New Name");
    }

    @Test
    public void testUpdatePresentationDefinitionInvalidJson() throws Exception {
        PresentationDefinition existingDefinition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Old Name")
                .definitionJson(DEFINITION_JSON)
                .tenantId(TENANT_ID)
                .build();

        PresentationDefinition updateRequest = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .definitionJson("invalid json")
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID))
                .thenReturn(existingDefinition);

        assertThrows(VPException.class, () -> presentationDefinitionService
                .updatePresentationDefinition(updateRequest, TENANT_ID));
    }

    @Test
    public void testDeletePresentationDefinition() throws Exception {
        PresentationDefinition existingDefinition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Old Name")
                .definitionJson(DEFINITION_JSON)
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID))
                .thenReturn(existingDefinition);
        doNothing().when(presentationDefinitionDAO).deletePresentationDefinition(DEFINITION_ID, TENANT_ID);

        presentationDefinitionService.deletePresentationDefinition(DEFINITION_ID, TENANT_ID);
        verify(presentationDefinitionDAO, times(1)).deletePresentationDefinition(DEFINITION_ID, TENANT_ID);
    }

    @Test
    public void testPresentationDefinitionExists() throws Exception {
        when(presentationDefinitionDAO.presentationDefinitionExists(DEFINITION_ID, TENANT_ID)).thenReturn(true);
        assertTrue(presentationDefinitionService.presentationDefinitionExists(DEFINITION_ID, TENANT_ID));
    }

    @Test
    public void testValidatePresentationDefinition() throws Exception {
        assertTrue(presentationDefinitionService.validatePresentationDefinition(DEFINITION_JSON));
        assertFalse(presentationDefinitionService.validatePresentationDefinition("invalid json"));
        assertFalse(presentationDefinitionService.validatePresentationDefinition(null));
        assertFalse(presentationDefinitionService.validatePresentationDefinition(""));
    }

    @Test
    public void testBuildPresentationDefinitionJson() throws Exception {
        String json = presentationDefinitionService
                .buildPresentationDefinitionJson("id-1", "Name", "Purpose", new String[]{"desc-1"});
        assertNotNull(json);
        assertTrue(json.contains("\"id-1\""));
    }

    @Test
    public void testGetPresentationDefinitionByName() throws Exception {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .definitionJson(DEFINITION_JSON)
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getPresentationDefinitionByName("Test Def", TENANT_ID)).thenReturn(definition);

        PresentationDefinition result = presentationDefinitionService
                .getPresentationDefinitionByName("Test Def", TENANT_ID);
        assertNotNull(result);
        assertEquals(result.getName(), "Test Def");
    }

    @Test
    public void testGetPresentationDefinitionByNameEmpty() throws Exception {
        assertThrows(VPException.class, () -> presentationDefinitionService
                .getPresentationDefinitionByName("", TENANT_ID));
    }

    @Test
    public void testGetClaimsFromPresentationDefinition() throws Exception {
        PresentationDefinition definition = new PresentationDefinition.Builder()
                .definitionId(DEFINITION_ID)
                .name("Test Def")
                .definitionJson(DEFINITION_JSON)
                .tenantId(TENANT_ID)
                .build();

        when(presentationDefinitionDAO.getPresentationDefinitionById(DEFINITION_ID, TENANT_ID)).thenReturn(definition);

        List<PresentationDefinitionService.InputDescriptorClaimsDTO> claimsList = presentationDefinitionService
                .getClaimsFromPresentationDefinition(DEFINITION_ID, TENANT_ID);
        assertNotNull(claimsList);
        assertEquals(claimsList.size(), 1);
        assertEquals(claimsList.get(0).getInputDescriptorId(), "desc-1");
        assertEquals(claimsList.get(0).getClaims().size(), 1);
        assertEquals(claimsList.get(0).getClaims().get(0).getName(), "email");
        assertEquals(claimsList.get(0).getClaims().get(0).getPath(), "$.credentialSubject.email");
    }
}
